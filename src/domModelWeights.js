export const DOM_MODEL = {
  "intercept": 1.176637,
  "metrics": {
    "accuracy": 0.842,
    "falseNegative": 163,
    "falsePositive": 532,
    "logLoss": 0.3902,
    "precision": 0.7929,
    "recall": 0.9259,
    "trueNegative": 1668,
    "truePositive": 2037
  },
  "trainedAt": "2026-06-21T13:28:06.859744+00:00",
  "trainingData": {
    "samples": 17600,
    "sources": [
      "data/dom_model_training_examples.csv",
      "data\\generated\\dom_phiusiil_features.csv"
    ]
  },
  "version": "dom-linear-v1",
  "weights": {
    "autocompleteOffSensitiveForm": 0.23129,
    "brandImpersonation": 1.385992,
    "externalPasswordForm": 0.569382,
    "externalSensitiveForm": 0.694972,
    "hasIframe": -2.596399,
    "hasPasswordField": -1.679661,
    "highExternalLinkRatio": -0.673736,
    "highExternalScriptRatio": -2.385723,
    "manyExternalIframes": -0.792537,
    "manyForms": 3.117323,
    "manyHiddenSensitiveInputs": -2.191883,
    "manySensitiveInputs": -0.04299,
    "multiplePasswordFields": 0.417587,
    "urgencyWithSensitive": 4.495741
  }
};
