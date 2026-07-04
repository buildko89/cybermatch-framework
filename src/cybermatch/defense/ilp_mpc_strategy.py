from src.cybermatch.config.simulation_config import SimulationConfig
import numpy as np
import cvxpy as cp
import logging
logger = logging.getLogger(__name__)
from typing import List, Dict, Tuple, Optional

class OptimizationEngine:
    """ILPおよびMPCの計算を担うエンジンクラス"""
    def __init__(self, config: SimulationConfig):
        self.config = config
        self.Q = np.diag(config.Q_diag)
        self.R = np.diag(config.R_diag)
        self.stats = {
            'ilp_solve_count': 0,
            'ilp_fallback_count': 0,
            'mpc_solve_count': 0,
            'mpc_fallback_count': 0,
        }

    def update_matching_ilp(self, x_val: np.ndarray, defense_weight: Optional[np.ndarray] = None) -> np.ndarray:
        """整数線形計画法によるマッチングの最適化"""
        M_var = cp.Variable((self.config.n_nodes, self.config.m_resources), boolean=True)
        weight = self.config.Q_diag if defense_weight is None else np.asarray(defense_weight, dtype=float)
        weighted_risk = weight * x_val 
        
        expected_reduction = cp.sum(cp.multiply(M_var, np.outer(weighted_risk, np.ones(self.config.m_resources)))) * self.config.r_max
        objective = cp.Minimize(-expected_reduction)

        constraints = []
        for j in range(self.config.m_resources):
            constraints += [cp.sum(M_var[:, j]) <= self.config.resource_capacity[j]]
        for i in range(self.config.n_nodes):
            constraints += [cp.sum(M_var[i, :]) <= 1]

        prob = cp.Problem(objective, constraints)
        self.stats['ilp_solve_count'] += 1
        
        try:
            # ソルバーを固定せず、利用可能な最適なものを自動選択
            prob.solve()
            if M_var.value is None or prob.status not in (cp.OPTIMAL, cp.OPTIMAL_INACCURATE):
                raise ValueError(f"ILP solver status={prob.status}, value={M_var.value}")
            M = np.round(M_var.value)
            if not self._matching_is_feasible(M):
                raise ValueError("ILP solver returned infeasible rounded matching")
            return M
        except Exception as e:
            self.stats['ilp_fallback_count'] += 1
            logger.warning(f"ILP solver failed ({e}). Falling back to greedy allocation.")
            return self._greedy_allocation(weighted_risk)

    def _matching_is_feasible(self, M: np.ndarray) -> bool:
        return (
            M.shape == (self.config.n_nodes, self.config.m_resources)
            and np.all(M >= -1e-8)
            and np.all(M <= 1 + 1e-8)
            and np.all(np.sum(M, axis=0) <= np.asarray(self.config.resource_capacity) + 1e-8)
            and np.all(np.sum(M, axis=1) <= 1 + 1e-8)
        )

    def _greedy_allocation(self, weighted_risk: np.ndarray) -> np.ndarray:
        M_fallback = np.zeros((self.config.n_nodes, self.config.m_resources))
        risk_order = np.argsort(weighted_risk)[::-1]
        caps = list(self.config.resource_capacity)
        
        for node_idx in risk_order:
            for res_idx in range(self.config.m_resources):
                if caps[res_idx] > 0:
                    M_fallback[node_idx, res_idx] = 1.0
                    caps[res_idx] -= 1
                    break
        return M_fallback

    def solve_mpc(
        self,
        x0: np.ndarray,
        r_prev: np.ndarray,
        M_current: np.ndarray,
        defense_weight: Optional[np.ndarray] = None,
        mpc_weight: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        Q_mpc = self._mpc_q_matrix(mpc_weight)
        x_var = cp.Variable((self.config.n_nodes, self.config.H + 1))
        r_var = cp.Variable((self.config.m_resources, self.config.H))
        s_var = cp.Variable((self.config.n_nodes, self.config.H))

        cost = 0
        constraints = [x_var[:, 0] == x0]
        d_k = self.config.d_base + self.config.beta * np.tanh(x0) 
        r_step_prev = r_prev

        for k in range(self.config.H):
            constraints += [
                x_var[:, k+1] == self.config.alpha * x_var[:, k] + d_k - M_current @ r_var[:, k] + s_var[:, k],
                s_var[:, k] >= 0,
                x_var[:, k+1] >= 0
            ]
            constraints += [
                r_var[:, k] >= 0,
                r_var[:, k] <= self.config.r_max,
                cp.sum(r_var[:, k]) <= self.config.R_total
            ]
            cost += cp.quad_form(x_var[:, k], Q_mpc)
            cost += cp.quad_form(r_var[:, k], self.R)
            cost += self.config.lambda_w * cp.sum_squares(r_var[:, k] - r_step_prev)
            cost += self.config.rho * cp.sum_squares(s_var[:, k])
            r_step_prev = r_var[:, k] 

        cost += cp.quad_form(x_var[:, self.config.H], Q_mpc)
        prob = cp.Problem(cp.Minimize(cost), constraints)
        self.stats['mpc_solve_count'] += 1
        
        try:
            prob.solve(solver=cp.OSQP, warm_start=True)
            if r_var[:, 0].value is None or prob.status not in (cp.OPTIMAL, cp.OPTIMAL_INACCURATE):
                raise ValueError(f"MPC solver status={prob.status}")
            return self._clip_resource_vector(r_var[:, 0].value)
        except Exception as e:
            logger.error(f"MPC solver error: {e}")
            self.stats['mpc_fallback_count'] += 1
            return self._greedy_resource_fallback(x0, M_current, defense_weight=defense_weight)

    def _mpc_q_matrix(self, mpc_weight: Optional[np.ndarray]) -> np.ndarray:
        if mpc_weight is None:
            return self.Q
        weight = np.asarray(mpc_weight, dtype=float)
        if weight.shape != (self.config.n_nodes,):
            raise ValueError(f"mpc_weight shape must be ({self.config.n_nodes},)")
        if np.any(weight < 0):
            raise ValueError("mpc_weight entries must be >= 0")
        return np.diag(weight)

    def _clip_resource_vector(self, r_value: np.ndarray) -> np.ndarray:
        r = np.clip(np.asarray(r_value, dtype=float), 0.0, self.config.r_max)
        total = float(np.sum(r))
        if total > self.config.R_total and total > 0:
            r *= self.config.R_total / total
        return r

    def _greedy_resource_fallback(
        self,
        x0: np.ndarray,
        M_current: np.ndarray,
        defense_weight: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        weight = self.config.Q_diag if defense_weight is None else np.asarray(defense_weight, dtype=float)
        scores = M_current.T @ (weight * x0)
        r = np.zeros(self.config.m_resources)
        remaining = self.config.R_total
        for res_idx in np.argsort(scores)[::-1]:
            if remaining <= 1e-12 or scores[res_idx] <= 0:
                break
            amount = min(self.config.r_max, remaining)
            r[res_idx] = amount
            remaining -= amount
        return r

