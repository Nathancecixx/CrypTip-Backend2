const Module = require('module');
const path = require('node:path');

const projectRoot = __dirname;
const compiledRoot = path.join(projectRoot, '.test-dist');
const originalResolve = Module._resolveFilename;

Module._resolveFilename = function (request, parent, isMain, options) {
  if (request.startsWith('@/')) {
    const target = path.join(compiledRoot, request.slice(2));
    return originalResolve.call(this, target, parent, isMain, options);
  }
  return originalResolve.call(this, request, parent, isMain, options);
};
