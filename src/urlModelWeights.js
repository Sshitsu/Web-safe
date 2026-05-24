export const URL_MODEL = {
  "intercept": -3.548197,
  "metrics": {
    "accuracy": 0.9904,
    "falseNegative": 32,
    "falsePositive": 0,
    "logLoss": 0.0471,
    "precision": 1.0,
    "recall": 0.9814,
    "trueNegative": 1600,
    "truePositive": 1691
  },
  "trainedAt": "2026-05-20T10:15:59.549451+00:00",
  "trainingData": {
    "benignSamples": 8000,
    "phishingSamples": 8000,
    "sources": [
      "OpenPhish Community Feed",
      "Phishing.Database active links",
      "Tranco top domains"
    ]
  },
  "version": "url-linear-trained-v1",
  "weights": {
    "deepPath": 0.697722,
    "encodedCharacters": 0.154879,
    "hasAtSymbol": 0.224671,
    "hasIpAddress": 0.451783,
    "hasPunycode": -0.162959,
    "highDigitRatio": 1.949796,
    "highEntropyHostname": 1.492329,
    "longUrl": 0.614967,
    "manyDots": 1.799498,
    "manyHyphens": 0.800638,
    "noHttps": 5.252813,
    "suspiciousKeywordCount": 1.438469,
    "veryLongUrl": 0.273262
  }
};
