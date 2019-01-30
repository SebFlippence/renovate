module.exports = {
  parse,
};

function parse(input) {
  if (!input) {
    return null;
  }
  const scheme = 'pkg:';
  if (!input.startsWith(scheme)) {
    return null;
  }
  const res = {};
  let remaining = input.substring(scheme.length);
  let parts = remaining.split('#');
  if (parts.length > 1) {
    [remaining, res.subpath] = parts;
  }
  parts = remaining.split('?');
  if (parts.length > 1) {
    [remaining, res.qualifiers] = parts;
  }
  parts = remaining.split('@');
  if (parts.length > 1) {
    [remaining, res.version] = parts;
  }
  parts = remaining.split('/');
  [res.datasource, ...remaining] = parts;
  if (remaining.length === 1) {
    [res.name] = remaining;
    res.lookupName = res.name;
  } else {
    res.name = remaining.pop();
    res.namespace = remaining.join('/').replace('%40', '@');
    res.lookupName = res.namespace + '/' + res.name;
  }
  if (res.qualifiers) {
    const allQualifiers = res.qualifiers.split('&');
    res.qualifiers = {};
    allQualifiers.forEach(qualifier => {
      const [key, val] = qualifier.split('=');
      res.qualifiers[key] = val;
    });
  } else {
    res.qualifiers = {};
  }
  return res;
}
