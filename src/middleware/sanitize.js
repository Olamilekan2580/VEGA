const { inHTMLData } = require('xss-filters');

function sanitizeString(value) {
  return inHTMLData(value).trim();
}

function sanitizeValue(value) {
  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }

  if (value && typeof value === 'object') {
    return sanitizeObject(value);
  }

  return value;
}

function sanitizeObject(input) {
  if (!input || typeof input !== 'object') {
    return input;
  }

  for (const key of Object.keys(input)) {
    input[key] = sanitizeValue(input[key]);
  }

  return input;
}

function sanitizeRequest(req, res, next) {
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }

  if (req.params) {
    req.params = sanitizeObject(req.params);
  }

  if (req.query && typeof req.query === 'object') {
    sanitizeObject(req.query);
  }

  next();
}

module.exports = { sanitizeRequest };
