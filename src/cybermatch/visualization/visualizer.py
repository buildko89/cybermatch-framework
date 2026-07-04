from src.cybermatch.config.simulation_config import SimulationConfig
import numpy as np
import matplotlib.pyplot as plt
import os
import logging
logger = logging.getLogger(__name__)
from typing import List, Dict, Tuple, Optional

class Visualizer:
    """結果の可視化を担うクラス"""
    @staticmethod
    def plot_results(history: dict, config: SimulationConfig, save_path: str = "simulation_result.png"):
        hx = np.array(history['x'])
        hr = np.array(history['r'])
        
        plt.figure(figsize=(12, 10))
        
        plt.subplot(2, 1, 1)
        for i in range(config.n_nodes):
            plt.plot(hx[:, i], label=f'Node {i} (Weight={config.Q_diag[i]})')
        plt.title('Asset Risk Levels Over Time')
        plt.ylabel('Risk Level')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        plt.subplot(2, 1, 2)
        for j in range(config.m_resources):
            plt.plot(hr[:, j], label=f'Resource {j}')
        plt.title('Defense Resource Allocation')
        plt.xlabel('Time Step')
        plt.ylabel('Resource Amount')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        
        # ファイル保存
        plt.savefig(save_path)
        logger.info(f"Result plot saved to {save_path}")
        
        if config.show_plot:
            plt.show()
        else:
            logger.info("show_plot=False. Plot saved without opening an interactive window.")
        plt.close()

if __name__ == "__main__":
    CONFIG_FILE = "config.json"
    OUTPUT_DIR = "output"

    # 1. 出力ディレクトリの作成
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 2. 設定の読み込みまたは作成
    if os.path.exists(CONFIG_FILE):
        config = SimulationConfig.from_json(CONFIG_FILE)
    else:
        logger.info("No config file found. Using defaults and creating config.json.")
        config = SimulationConfig()
        config.to_json(CONFIG_FILE)

    # 3. シミュレーターの初期化と実行
    sim = CyberDefenseSimulator(config)
    results = sim.run()
    sim.save_outputs(OUTPUT_DIR)

    # 4. 可視化と結果の保存
    # 使用した設定も記録として保存
    config.to_json(os.path.join(OUTPUT_DIR, "used_config.json"))
    
    # グラフの保存先を指定
    Visualizer.plot_results(
        results, 
        config, 
        save_path=os.path.join(OUTPUT_DIR, "simulation_result.png")
    )
