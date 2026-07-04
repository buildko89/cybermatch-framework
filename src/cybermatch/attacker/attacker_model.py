from src.cybermatch.config.simulation_config import SimulationConfig
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

@dataclass
class AttackerModel:
    """一般的なITシステムを想定した攻撃者の意思決定モデル"""

    enabled: bool = False

    # 攻撃先選択
    attack_budget: float = 3.0
    target_selection: str = "greedy"  # "greedy" | "random" | "adaptive"
    greedy_mode: str = "utility"  # "legacy" | "weighted_risk" | "utility"
    attacker_belief: Optional[np.ndarray] = None

    # 利得・コスト構造
    compromised_value: float = 0.0
    total_cost: float = 0.0
    actual_gain: float = 0.0
    actual_cost: float = 0.0
    perceived_gain: float = 0.0
    perceived_cost: float = 0.0
    confidence: float = 1.0
    frustration: float = 0.0
    max_frustration: float = 0.0
    frustration_sum: float = 0.0
    frustration_steps: int = 0
    frustration_retreats: int = 0
    ai_uncertainty_cost: float = 0.0
    ai_replanning_cost: float = 0.0
    ai_search_cost: float = 0.0
    ai_operational_risk_cost: float = 0.0
    ai_trust_degradation_cost: float = 0.0

    effort_cost_rate: float = 0.3
    detection_penalty: float = 1.0
    deception_waste: float = 0.0
    defense_cost_rate: float = 1.0
    detection_sensitivity: float = 1.0
    success_base_rate: float = 1.0
    success_defense_decay: float = 0.5
    belief_learning_enabled: bool = False
    belief_success_boost: float = 1.0
    belief_failure_decay: float = 0.8
    belief_detection_decay: float = 0.5
    belief_decoy_decay: float = 0.1
    belief_min: float = 0.0
    belief_max: float = 20.0
    adaptive_attacker_enabled: bool = False
    adaptive_success_weight: float = 1.0
    adaptive_decoy_weight: float = 2.0
    adaptive_detection_weight: float = 1.5
    adaptive_preference_enabled: bool = False
    adaptive_preference_weight: float = 2.0
    adaptive_success_reward: float = 1.0
    adaptive_critical_reward: float = 3.0
    adaptive_decoy_penalty: float = 2.0
    adaptive_detection_penalty: float = 1.5
    adaptive_path_enabled: bool = False
    path_preference_weight: float = 3.0
    path_success_reward: float = 1.0
    path_critical_reward: float = 5.0
    path_decoy_penalty: float = 2.0
    path_detection_penalty: float = 1.5
    adaptive_planning_enabled: bool = False
    planning_depth: int = 2
    planning_success_weight: float = 1.0
    planning_critical_weight: float = 5.0
    planning_decoy_penalty: float = 2.0
    planning_detection_penalty: float = 1.5
    trust_enabled: bool = False
    trust_decoy_penalty: float = 0.20
    trust_credential_penalty: float = 0.30
    trust_detection_penalty: float = 0.15
    trust_success_reward: float = 0.05
    expected_utility_enabled: bool = False
    expected_gain_weight: float = 1.0
    expected_success_weight: float = 1.0
    expected_detection_cost: float = 1.0
    expected_search_cost: float = 1.0
    expected_trust_weight: float = 1.0
    attacker_mission: str = "none"
    mission_expected_utility_weight: float = 1.0
    mission_trust_weight: float = 1.0
    mission_planning_weight: float = 1.0
    mission_critical_target_weight: float = 1.0
    adaptive_mission_attacker_enabled: bool = False
    observed_defense_strategy: str = "none"
    defense_effectiveness_memory: float = 0.0
    strategy_failure_memory: float = 0.0
    strategy_success_memory: float = 0.0
    adaptation_count: int = 0
    ttp_change_count: int = 0
    strategy_avoidance_score: float = 0.0
    alternative_path_usage: float = 0.0
    lateral_enabled: bool = False
    lateral_success_prob: float = 0.8
    lateral_detection_prob: float = 0.2
    adjacency_matrix: Optional[np.ndarray] = None
    entry_nodes: Optional[List[int]] = None
    node_type: Optional[List[str]] = None
    critical_nodes: Optional[List[int]] = None

    # 撤退条件
    retreat_threshold: float = -2.0
    patience: int = 10
    perceived_no_progress_threshold: float = 0.0
    perceived_utility_enabled: bool = False
    perceived_success_confidence: float = 1.0
    perceived_decoy_penalty: float = 1.0
    perceived_detection_penalty: float = 1.0
    perceived_uncertainty_decay: float = 0.95
    retreat_based_on: str = "actual"
    frustration_enabled: bool = False
    frustration_decoy_hit: float = 3.0
    frustration_credential_trap: float = 2.0
    frustration_detection: float = 1.0
    frustration_path_change: float = 0.5
    frustration_no_progress: float = 0.5
    frustration_decay: float = 0.95
    frustration_retreat_threshold: float = 10.0

    # 内部状態
    no_success_steps: int = 0
    retreated: bool = False
    last_selection_score: Optional[np.ndarray] = None
    last_selected_target: int = -1
    previous_selected_target: int = -1
    current_node: int = 0
    visited_nodes: Optional[set] = None
    compromised_nodes: Optional[set] = None
    node_success_memory: Optional[Dict[int, float]] = None
    node_decoy_memory: Optional[Dict[int, float]] = None
    node_detection_memory: Optional[Dict[int, float]] = None
    node_preference_score: Optional[Dict[int, float]] = None
    path_success_memory: Optional[Dict[str, float]] = None
    path_decoy_memory: Optional[Dict[str, float]] = None
    path_detection_memory: Optional[Dict[str, float]] = None
    path_preference_score: Optional[Dict[str, float]] = None
    current_attack_path: Optional[List[int]] = None
    last_planning_score: Optional[np.ndarray] = None
    last_planned_path: Optional[List[int]] = None
    last_planned_path_score: float = 0.0
    node_trust_score: Optional[Dict[int, float]] = None
    last_expected_utility: Optional[np.ndarray] = None
    last_expected_gain_estimate: Optional[np.ndarray] = None
    last_expected_detection_risk: Optional[np.ndarray] = None
    last_expected_search_cost: Optional[np.ndarray] = None

    def __post_init__(self):
        if self.attacker_belief is None:
            self.current_belief = None
        else:
            self.current_belief = np.clip(
                np.asarray(self.attacker_belief, dtype=float).copy(),
                self.belief_min,
                self.belief_max,
            )
        if self.entry_nodes:
            self.current_node = int(self.entry_nodes[0])
        self.visited_nodes = {int(self.current_node)}
        self.compromised_nodes = {int(self.current_node)}
        if self.adjacency_matrix is not None:
            self.adjacency_matrix = np.asarray(self.adjacency_matrix, dtype=int)
        n_nodes = int(len(self.current_belief)) if self.current_belief is not None else 0
        self.node_success_memory = {node_id: 0.0 for node_id in range(n_nodes)}
        self.node_decoy_memory = {node_id: 0.0 for node_id in range(n_nodes)}
        self.node_detection_memory = {node_id: 0.0 for node_id in range(n_nodes)}
        self.node_preference_score = {node_id: 0.0 for node_id in range(n_nodes)}
        self.path_success_memory = {}
        self.path_decoy_memory = {}
        self.path_detection_memory = {}
        self.path_preference_score = {}
        self.current_attack_path = [int(self.current_node)]
        self.last_planning_score = np.zeros(n_nodes, dtype=float)
        self.last_planned_path = []
        self.last_planned_path_score = 0.0
        self.node_trust_score = {node_id: 1.0 for node_id in range(n_nodes)}
        self.last_expected_utility = np.zeros(n_nodes, dtype=float)
        self.last_expected_gain_estimate = np.zeros(n_nodes, dtype=float)
        self.last_expected_detection_risk = np.zeros(n_nodes, dtype=float)
        self.last_expected_search_cost = np.zeros(n_nodes, dtype=float)
        self.adaptation_history = []

    @property
    def utility(self) -> float:
        return self.actual_utility

    @property
    def actual_utility(self) -> float:
        return self.actual_gain - self.actual_cost

    @property
    def perceived_utility(self) -> float:
        return self.perceived_gain - self.perceived_cost

    @property
    def mean_frustration(self) -> float:
        if self.frustration_steps <= 0:
            return float(self.frustration)
        return float(self.frustration_sum / self.frustration_steps)

    def select_attack(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        previous_target = self.last_selected_target
        self.last_selection_score = np.zeros_like(x_current, dtype=float)
        self.last_selected_target = -1
        if not self.enabled or self.retreated:
            return np.zeros_like(x_current, dtype=float)

        attack_vector = np.zeros_like(x_current, dtype=float)
        if self.target_selection == "greedy":
            score = self._reachable_score(self.calculate_greedy_score(x_current, M_current))
            target_idx = int(np.argmax(score))
        elif self.target_selection == "random":
            score = np.zeros_like(x_current, dtype=float)
            candidates = self.reachable_nodes(len(x_current))
            target_idx = int(np.random.choice(candidates))
        elif self.target_selection == "adaptive":
            score = self._reachable_score(self.calculate_adaptive_score(x_current, M_current))
            target_idx = int(np.argmax(score))
        else:
            raise ValueError(f"Unsupported target_selection: {self.target_selection}")

        self.last_selection_score = score
        self.previous_selected_target = previous_target
        self.last_selected_target = target_idx
        attack_vector[target_idx] = self.attack_budget
        return attack_vector

    def _select_greedy_target(self, x_current: np.ndarray, M_current: np.ndarray) -> int:
        score = self._reachable_score(self.calculate_greedy_score(x_current, M_current))
        return int(np.argmax(score))

    def reachable_nodes(self, n_nodes: int) -> List[int]:
        if not self.lateral_enabled or self.adjacency_matrix is None:
            return list(range(n_nodes))
        neighbors = np.flatnonzero(self.adjacency_matrix[int(self.current_node)] > 0).astype(int).tolist()
        return neighbors or [int(self.current_node)]

    def _reachable_score(self, score: np.ndarray) -> np.ndarray:
        if not self.lateral_enabled:
            return score
        masked = np.full_like(score, -1.0e12, dtype=float)
        for node_idx in self.reachable_nodes(len(score)):
            masked[node_idx] = score[node_idx]
        return masked

    def record_lateral_result(self, target_idx: int, success: bool) -> None:
        if not self.lateral_enabled or target_idx < 0:
            return
        if success:
            self.current_node = int(target_idx)
            self.compromised_nodes.add(int(target_idx))
            if self.current_attack_path is None:
                self.current_attack_path = [int(target_idx)]
            elif not self.current_attack_path or self.current_attack_path[-1] != int(target_idx):
                self.current_attack_path.append(int(target_idx))
        self.visited_nodes.add(int(target_idx))

    def calculate_greedy_score(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        defense_strength = M_current.sum(axis=1)
        attacker_belief = self._attacker_belief_or_default(len(x_current))

        if self.greedy_mode == "legacy":
            return x_current - defense_strength
        if self.greedy_mode == "weighted_risk":
            return attacker_belief * x_current - defense_strength
        if self.greedy_mode == "utility":
            expected_success_prob = self.success_base_rate * np.exp(
                -self.success_defense_decay * defense_strength
            )
            expected_success_prob = np.clip(expected_success_prob, 0.0, 1.0)
            expected_gain = attacker_belief * (x_current + self.attack_budget) * expected_success_prob
            expected_cost = (
                self.attack_budget * self.effort_cost_rate
                + self.defense_cost_rate * defense_strength
                + self.detection_penalty * self.detection_sensitivity * defense_strength
            )
            return expected_gain - expected_cost
        raise ValueError(f"Unsupported greedy_mode: {self.greedy_mode}")

    def calculate_adaptive_score(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        score = self.calculate_greedy_score(x_current, M_current)
        if not self.adaptive_attacker_enabled:
            return score
        n_nodes = len(score)
        success_memory = self._memory_array(self.node_success_memory, n_nodes)
        decoy_memory = self._memory_array(self.node_decoy_memory, n_nodes)
        detection_memory = self._memory_array(self.node_detection_memory, n_nodes)
        preference_score = self._memory_array(self.node_preference_score, n_nodes)
        preference_weight = self.adaptive_preference_weight if self.adaptive_preference_enabled else 0.0
        path_score = self._path_candidate_score(n_nodes)
        path_weight = self.path_preference_weight if self.adaptive_path_enabled else 0.0
        planning_score = self._planning_candidate_score(x_current, M_current)
        expected_utility = self._expected_utility(x_current, M_current)
        trust_score = self.trust_vector(n_nodes) if self.trust_enabled else np.ones(n_nodes, dtype=float)
        critical_bonus = np.zeros(n_nodes, dtype=float)
        if self.attacker_mission == "critical_hunter":
            for node in self.critical_nodes or []:
                if 0 <= int(node) < n_nodes:
                    critical_bonus[int(node)] = self.mission_critical_target_weight * max(float(np.max(self.current_belief)), 1.0)
        mission_adaptation_score = self._mission_adaptation_score(n_nodes, expected_utility, planning_score, trust_score)
        return (
            score
            + self.adaptive_success_weight * success_memory
            + preference_weight * preference_score
            + path_weight * path_score
            + self.mission_planning_weight * planning_score
            + self.mission_expected_utility_weight * expected_utility
            + self.mission_trust_weight * trust_score
            + critical_bonus
            + mission_adaptation_score
            - self.adaptive_decoy_weight * decoy_memory
            - self.adaptive_detection_weight * detection_memory
        )

    def _mission_adaptation_score(
        self,
        n_nodes: int,
        expected_utility: np.ndarray,
        planning_score: np.ndarray,
        trust_score: np.ndarray,
    ) -> np.ndarray:
        if not self.adaptive_mission_attacker_enabled:
            return np.zeros(n_nodes, dtype=float)
        pressure = float(np.clip(self.defense_effectiveness_memory, 0.0, 5.0))
        if pressure <= 0.0:
            return np.zeros(n_nodes, dtype=float)
        score = np.zeros(n_nodes, dtype=float)
        visited = {int(node) for node in (self.visited_nodes or set())}
        unvisited_bonus = np.array([0.0 if node in visited else 1.0 for node in range(n_nodes)], dtype=float)
        reachable = set(int(node) for node in self.reachable_nodes(n_nodes))
        lateral_bonus = np.array([1.0 if node in reachable and node != int(self.current_node) else 0.0 for node in range(n_nodes)], dtype=float)
        if self.attacker_mission == "profit":
            score += pressure * (0.60 * unvisited_bonus + 0.20 * lateral_bonus + 0.20 * np.maximum(expected_utility, 0.0))
        elif self.attacker_mission == "persistence":
            score += pressure * (0.70 * trust_score + 0.30 * lateral_bonus)
        elif self.attacker_mission == "critical_hunter":
            score += pressure * (0.65 * planning_score + 0.35 * unvisited_bonus)
        elif self.attacker_mission == "achievement":
            score += pressure * (0.50 * np.maximum(expected_utility, 0.0) + 0.30 * planning_score + 0.20 * unvisited_bonus)
        return score

    def observe_defense_strategy(
        self,
        strategy: str,
        objective_score: float,
        failure_reason: str,
    ) -> str:
        if not self.adaptive_mission_attacker_enabled:
            return "non_adaptive"
        previous_strategy = self.observed_defense_strategy
        self.observed_defense_strategy = str(strategy or "none")
        pressure = float(np.clip(1.0 - float(objective_score), 0.0, 1.0))
        mission_failure = str(failure_reason or "none") != "none"
        if mission_failure or pressure > 0.45:
            self.strategy_failure_memory = 0.80 * self.strategy_failure_memory + pressure + (0.25 if mission_failure else 0.0)
            self.strategy_success_memory *= 0.85
        else:
            self.strategy_success_memory = 0.80 * self.strategy_success_memory + float(objective_score)
            self.strategy_failure_memory *= 0.85
        self.defense_effectiveness_memory = 0.70 * self.defense_effectiveness_memory + 0.30 * max(
            self.strategy_failure_memory,
            pressure,
        )
        should_adapt = self.defense_effectiveness_memory > 0.35
        changed_strategy = previous_strategy not in ("", "none", self.observed_defense_strategy)
        if should_adapt:
            self.adaptation_count += 1
            self.ttp_change_count += 1
            if changed_strategy:
                self.strategy_avoidance_score += 0.5
            self.alternative_path_usage += self._alternative_path_increment()
            action = self._adaptation_action()
            self.adaptation_history.append(action)
            return action
        self.adaptation_history.append("observe")
        return "observe"

    def _alternative_path_increment(self) -> float:
        if self.adaptive_path_enabled or self.lateral_enabled:
            return 1.0
        return 0.5

    def _adaptation_action(self) -> str:
        if self.attacker_mission == "profit":
            return "target_switch"
        if self.attacker_mission == "persistence":
            return "stealth_lateral_shift"
        if self.attacker_mission == "critical_hunter":
            return "alternative_critical_path"
        if self.attacker_mission == "achievement":
            self.frustration_retreat_threshold += 0.25
            self.patience += 1
            return "risk_tolerance_increase"
        return "generic_ttp_change"

    def _memory_array(self, memory: Optional[Dict[int, float]], n_nodes: int) -> np.ndarray:
        if memory is None:
            return np.zeros(n_nodes, dtype=float)
        return np.array([float(memory.get(node_id, 0.0)) for node_id in range(n_nodes)], dtype=float)

    def memory_vector(self, memory_name: str, n_nodes: int) -> np.ndarray:
        memory = getattr(self, memory_name)
        return self._memory_array(memory, n_nodes)

    def trust_vector(self, n_nodes: int) -> np.ndarray:
        if self.node_trust_score is None:
            return np.ones(n_nodes, dtype=float)
        return np.array([float(self.node_trust_score.get(node_id, 1.0)) for node_id in range(n_nodes)], dtype=float)

    def _expected_utility(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        n_nodes = len(x_current)
        if not self.expected_utility_enabled:
            self.last_expected_utility = np.zeros(n_nodes, dtype=float)
            self.last_expected_gain_estimate = np.zeros(n_nodes, dtype=float)
            self.last_expected_detection_risk = np.zeros(n_nodes, dtype=float)
            self.last_expected_search_cost = np.zeros(n_nodes, dtype=float)
            return self.last_expected_utility

        defense_strength = M_current.sum(axis=1)
        belief = self._attacker_belief_or_default(n_nodes)
        success_probability = np.clip(
            self.success_base_rate * np.exp(-self.success_defense_decay * defense_strength),
            0.0,
            1.0,
        )
        detection_risk = np.clip(
            self.detection_sensitivity * defense_strength / np.maximum(defense_strength + 1.0, 1.0),
            0.0,
            1.0,
        )
        trust = np.power(np.clip(self.trust_vector(n_nodes), 0.0, 1.0), self.expected_trust_weight)
        expected_gain = self.expected_gain_weight * belief * (x_current + self.attack_budget)
        search_cost = self._expected_search_cost(n_nodes)
        expected_utility = (
            expected_gain
            * (self.expected_success_weight * success_probability)
            * trust
            - self.expected_detection_cost * detection_risk
            - self.expected_search_cost * search_cost
        )
        self.last_expected_utility = np.asarray(expected_utility, dtype=float)
        self.last_expected_gain_estimate = np.asarray(expected_gain, dtype=float)
        self.last_expected_detection_risk = np.asarray(detection_risk, dtype=float)
        self.last_expected_search_cost = np.asarray(search_cost, dtype=float)
        return self.last_expected_utility

    def _expected_search_cost(self, n_nodes: int) -> np.ndarray:
        if not self.lateral_enabled or self.adjacency_matrix is None:
            return np.zeros(n_nodes, dtype=float)
        reachable = set(int(node) for node in self.reachable_nodes(n_nodes))
        visited = set(int(node) for node in (self.visited_nodes or set()))
        costs = np.ones(n_nodes, dtype=float)
        for node_id in range(n_nodes):
            if node_id == int(self.current_node):
                costs[node_id] = 0.0
            elif node_id in reachable:
                costs[node_id] = 0.25
            elif node_id in visited:
                costs[node_id] = 0.5
        return costs

    def _path_key(self, nodes: List[int]) -> str:
        return "->".join(str(int(node)) for node in nodes)

    def path_key_for_target(self, target_idx: int) -> str:
        path = list(self.current_attack_path or [int(self.current_node)])
        target = int(target_idx)
        if not path or path[-1] != target:
            path.append(target)
        return self._path_key(path)

    def _path_candidate_score(self, n_nodes: int) -> np.ndarray:
        if not self.adaptive_path_enabled or self.path_preference_score is None:
            return np.zeros(n_nodes, dtype=float)
        return np.array(
            [float(self.path_preference_score.get(self.path_key_for_target(node_id), 0.0)) for node_id in range(n_nodes)],
            dtype=float,
        )

    def path_preference_vector(self) -> np.ndarray:
        if not self.path_preference_score:
            return np.zeros(0, dtype=float)
        return np.asarray(list(self.path_preference_score.values()), dtype=float)

    def _planning_candidate_score(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        n_nodes = len(x_current)
        if not self.adaptive_planning_enabled or self.planning_depth <= 0:
            self.last_planning_score = np.zeros(n_nodes, dtype=float)
            self.last_planned_path = []
            self.last_planned_path_score = 0.0
            return self.last_planning_score

        planning_score = np.full(n_nodes, -1.0e12, dtype=float)
        best_path: List[int] = []
        best_score = -1.0e12
        current_node = int(self.current_node)
        for target in self.reachable_nodes(n_nodes):
            target = int(target)
            value, path = self._plan_path_value(
                current_node=target,
                depth=int(self.planning_depth) - 1,
                x_current=x_current,
                M_current=M_current,
                path=[current_node, target] if current_node != target else [target],
                visited={current_node, target},
            )
            immediate = self._planning_node_value(target, M_current)
            score = immediate + value
            if self.trust_enabled:
                score *= float(self.trust_vector(n_nodes)[target])
            planning_score[target] = score
            if score > best_score:
                best_score = float(score)
                best_path = path if path else ([current_node, target] if current_node != target else [target])

        self.last_planning_score = planning_score
        self.last_planned_path = [int(node) for node in best_path]
        self.last_planned_path_score = float(best_score if best_score > -1.0e11 else 0.0)
        return planning_score

    def _plan_path_value(
        self,
        current_node: int,
        depth: int,
        x_current: np.ndarray,
        M_current: np.ndarray,
        path: List[int],
        visited: set,
    ) -> Tuple[float, List[int]]:
        if depth <= 0:
            return 0.0, list(path)

        best_value = 0.0
        best_path = list(path)
        for neighbor in self._planning_neighbors(int(current_node), len(x_current)):
            neighbor = int(neighbor)
            if neighbor in visited and len(visited) < len(x_current):
                continue
            immediate = self._planning_node_value(neighbor, M_current)
            future, future_path = self._plan_path_value(
                current_node=neighbor,
                depth=depth - 1,
                x_current=x_current,
                M_current=M_current,
                path=path + [neighbor],
                visited=visited | {neighbor},
            )
            total = immediate + future
            if total > best_value:
                best_value = float(total)
                best_path = future_path
        return best_value, best_path

    def _planning_neighbors(self, node_idx: int, n_nodes: int) -> List[int]:
        if self.lateral_enabled and self.adjacency_matrix is not None:
            neighbors = np.flatnonzero(self.adjacency_matrix[int(node_idx)] > 0).astype(int).tolist()
            return neighbors or [int(node_idx)]
        return list(range(n_nodes))

    def _planning_node_value(self, node_idx: int, M_current: np.ndarray) -> float:
        defense_strength = float(M_current[int(node_idx)].sum())
        success_prob = float(np.clip(
            self.success_base_rate * np.exp(-self.success_defense_decay * defense_strength),
            0.0,
            1.0,
        ))
        detection_prob = float(np.clip(
            self.detection_sensitivity * defense_strength / max(defense_strength + 1.0, 1.0),
            0.0,
            1.0,
        ))
        node_type = self.node_type[int(node_idx)] if self.node_type and int(node_idx) < len(self.node_type) else "real"
        critical_nodes = set(int(node) for node in (self.critical_nodes or []))
        success_reward = self.planning_success_weight * success_prob
        critical_reward = self.planning_critical_weight * success_prob if int(node_idx) in critical_nodes else 0.0
        decoy_penalty = self.planning_decoy_penalty if node_type == "decoy" else 0.0
        detection_penalty = self.planning_detection_penalty * detection_prob
        return float(success_reward + critical_reward - decoy_penalty - detection_penalty)

    def update_trust(
        self,
        target_idx: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
        credential_decoy_trigger: bool = False,
    ) -> None:
        if not self.trust_enabled or target_idx < 0:
            return
        if self.node_trust_score is None:
            n_nodes = int(len(self.current_belief)) if self.current_belief is not None else int(target_idx) + 1
            self.node_trust_score = {node_id: 1.0 for node_id in range(n_nodes)}
        target = int(target_idx)
        current = float(self.node_trust_score.get(target, 1.0))
        if attacked_decoy:
            current -= self.trust_decoy_penalty
        if credential_decoy_trigger:
            current -= self.trust_credential_penalty
        if detected:
            current -= self.trust_detection_penalty
        if success:
            current += self.trust_success_reward
        self.node_trust_score[target] = float(np.clip(current, 0.0, 1.0))

    def serialized_path_preference(self) -> str:
        if not self.path_preference_score:
            return ""
        parts = [
            f"{key}:{float(value):.6g}"
            for key, value in sorted(self.path_preference_score.items())
            if abs(float(value)) > 0.0
        ]
        return "|".join(parts)

    def update_memory(
        self,
        target_idx: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
        critical_reached: bool = False,
        path_key: Optional[str] = None,
    ) -> None:
        if target_idx < 0:
            return
        if self.node_success_memory is None:
            self.node_success_memory = {}
        if self.node_decoy_memory is None:
            self.node_decoy_memory = {}
        if self.node_detection_memory is None:
            self.node_detection_memory = {}
        if self.node_preference_score is None:
            self.node_preference_score = {}
        if self.path_success_memory is None:
            self.path_success_memory = {}
        if self.path_decoy_memory is None:
            self.path_decoy_memory = {}
        if self.path_detection_memory is None:
            self.path_detection_memory = {}
        if self.path_preference_score is None:
            self.path_preference_score = {}
        target = int(target_idx)
        self.node_success_memory.setdefault(target, 0.0)
        self.node_decoy_memory.setdefault(target, 0.0)
        self.node_detection_memory.setdefault(target, 0.0)
        self.node_preference_score.setdefault(target, 0.0)
        if success:
            self.node_success_memory[target] += 1.0
        if attacked_decoy:
            self.node_decoy_memory[target] += 1.0
        if detected:
            self.node_detection_memory[target] += 1.0
        if self.adaptive_preference_enabled:
            if success:
                self.node_preference_score[target] += self.adaptive_success_reward
            if critical_reached:
                self.node_preference_score[target] += self.adaptive_critical_reward
            if attacked_decoy:
                self.node_preference_score[target] -= self.adaptive_decoy_penalty
            if detected:
                self.node_preference_score[target] -= self.adaptive_detection_penalty
        if self.adaptive_path_enabled:
            key = path_key or self.path_key_for_target(target)
            self.path_success_memory.setdefault(key, 0.0)
            self.path_decoy_memory.setdefault(key, 0.0)
            self.path_detection_memory.setdefault(key, 0.0)
            self.path_preference_score.setdefault(key, 0.0)
            if critical_reached:
                self.path_success_memory[key] += 1.0
            if attacked_decoy:
                self.path_decoy_memory[key] += 1.0
            if detected:
                self.path_detection_memory[key] += 1.0
            if success:
                self.path_preference_score[key] += self.path_success_reward
            if critical_reached:
                self.path_preference_score[key] += self.path_critical_reward
            if attacked_decoy:
                self.path_preference_score[key] -= self.path_decoy_penalty
            if detected:
                self.path_preference_score[key] -= self.path_detection_penalty

    def _attacker_belief_or_default(self, n_nodes: int) -> np.ndarray:
        if self.current_belief is None:
            return np.ones(n_nodes)
        attacker_belief = np.asarray(self.current_belief, dtype=float)
        if attacker_belief.shape != (n_nodes,):
            raise ValueError(f"attacker_belief length must equal x_current length ({n_nodes})")
        return attacker_belief

    def update_belief(
        self,
        target_idx: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
    ) -> None:
        if not self.belief_learning_enabled or target_idx < 0 or self.current_belief is None:
            return

        if success:
            self.current_belief[target_idx] += self.belief_success_boost
        else:
            self.current_belief[target_idx] *= self.belief_failure_decay
        if detected:
            self.current_belief[target_idx] *= self.belief_detection_decay
        if attacked_decoy:
            self.current_belief[target_idx] *= self.belief_decoy_decay
        self.current_belief = np.clip(self.current_belief, self.belief_min, self.belief_max)

    def update_state(
        self,
        gained: float,
        detected: bool,
        success: bool,
        deception_waste_step: float = 0.0,
        detection_penalty_step: float = 0.0,
        perceived_gained: Optional[float] = None,
        attacked_decoy: bool = False,
        credential_decoy_trigger: bool = False,
        path_changed: bool = False,
        no_progress: bool = False,
    ) -> None:
        if not self.enabled or self.retreated:
            return

        actual_cost_step = self.attack_budget * self.effort_cost_rate
        if detected:
            actual_cost_step += self.detection_penalty + detection_penalty_step
        actual_cost_step += self.deception_waste + deception_waste_step

        self.actual_gain += gained
        self.actual_cost += actual_cost_step
        self.compromised_value = self.actual_gain
        self.total_cost = self.actual_cost

        if self.perceived_utility_enabled:
            perceived_gain_step = (
                (perceived_gained if perceived_gained is not None else gained)
                * self.confidence
                * self.perceived_success_confidence
            )
            perceived_cost_step = self.attack_budget * self.effort_cost_rate
            if detected:
                perceived_cost_step += (self.detection_penalty + detection_penalty_step) * self.perceived_detection_penalty
            if attacked_decoy:
                perceived_cost_step += (self.deception_waste + deception_waste_step + self.perceived_decoy_penalty)
            if credential_decoy_trigger:
                perceived_cost_step += self.perceived_decoy_penalty
            self.perceived_gain += perceived_gain_step
            self.perceived_cost += perceived_cost_step
            if attacked_decoy or credential_decoy_trigger or detected:
                self.confidence *= self.perceived_uncertainty_decay
        else:
            self.perceived_gain = self.actual_gain
            self.perceived_cost = self.actual_cost
            self.confidence = 1.0

        if self.frustration_enabled:
            self.frustration *= self.frustration_decay
            self.ai_uncertainty_cost *= self.frustration_decay
            self.ai_replanning_cost *= self.frustration_decay
            self.ai_search_cost *= self.frustration_decay
            self.ai_operational_risk_cost *= self.frustration_decay
            self.ai_trust_degradation_cost *= self.frustration_decay
            if attacked_decoy:
                self.frustration += self.frustration_decoy_hit
                self.ai_uncertainty_cost += self.frustration_decoy_hit
            if credential_decoy_trigger:
                self.frustration += self.frustration_credential_trap
                self.ai_trust_degradation_cost += self.frustration_credential_trap
            if detected:
                self.frustration += self.frustration_detection
                self.ai_operational_risk_cost += self.frustration_detection
            if path_changed:
                self.frustration += self.frustration_path_change
                self.ai_replanning_cost += self.frustration_path_change
            if no_progress:
                self.frustration += self.frustration_no_progress
                self.ai_search_cost += self.frustration_no_progress
        else:
            self.frustration = 0.0
            self.ai_uncertainty_cost = 0.0
            self.ai_replanning_cost = 0.0
            self.ai_search_cost = 0.0
            self.ai_operational_risk_cost = 0.0
            self.ai_trust_degradation_cost = 0.0
        self.max_frustration = max(float(self.max_frustration), float(self.frustration))
        self.frustration_sum += float(self.frustration)
        self.frustration_steps += 1

        # Patience counter driven by perceived_gained when provided (oracle-leak fix).
        # An attacker who perceives progress (perceived_gained > threshold) does not count
        # the step as "no progress", even if true gain is 0 (e.g., decoy attack).
        # Falls back to true success when perceived_gained is not provided (legacy path).
        if perceived_gained is not None:
            if perceived_gained > self.perceived_no_progress_threshold:
                self.no_success_steps = 0
            else:
                self.no_success_steps += 1
        else:
            if success:
                self.no_success_steps = 0
            else:
                self.no_success_steps += 1

        if self.retreat_based_on == "frustration":
            should_retreat = self.frustration > self.frustration_retreat_threshold
        else:
            retreat_utility = self.perceived_utility if self.retreat_based_on == "perceived" else self.actual_utility
            should_retreat = retreat_utility < self.retreat_threshold
        if should_retreat or self.no_success_steps >= self.patience:
            if self.retreat_based_on == "frustration" and self.frustration > self.frustration_retreat_threshold:
                self.frustration_retreats += 1
            self.retreated = True

