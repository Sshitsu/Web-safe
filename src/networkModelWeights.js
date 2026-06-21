export const NETWORK_MODEL = {
  "intercept": -2.777543,
  "metrics": {
    "accuracy": 0.9,
    "falseNegative": 0,
    "falsePositive": 2,
    "logLoss": 0.185,
    "precision": 0.8333,
    "recall": 1.0,
    "trueNegative": 8,
    "truePositive": 10
  },
  "trainedAt": "2026-06-21T13:26:30.903980+00:00",
  "trainingData": {
    "samples": 80,
    "sources": [
      "data/network_model_training_examples.csv",
      "data\\generated\\network_runtime_features.csv"
    ]
  },
  "version": "network-linear-v1",
  "weights": {
    "dnsNoAddress": -0.533895,
    "dnsNoNameServers": 1.500466,
    "dnsShortTtl": -1.133969,
    "dnsUnavailable": -0.623927,
    "noMxRecord": 0.955086,
    "rdapUnavailable": 4.757366,
    "recentDomainChange7": -0.079822,
    "youngDomain30": 5.532505,
    "youngDomain7": 4.744673,
    "youngDomain90": 3.28775
  }
};
