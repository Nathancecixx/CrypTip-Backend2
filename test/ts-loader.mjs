import { readFile, access } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import ts from 'typescript';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tsExtensions = ['.ts', '.tsx'];

async function fileExists(p) {
  try {
    await access(p);
    return true;
  } catch (err) {
    if (err && err.code === 'ENOENT') return false;
    throw err;
  }
}

async function resolveWithExtensions(resolvedPath) {
  for (const ext of tsExtensions) {
    const full = resolvedPath.endsWith(ext) ? resolvedPath : resolvedPath + ext;
    if (await fileExists(full)) {
      return pathToFileURL(full).href;
    }
  }
  return null;
}

export async function resolve(specifier, context, defaultResolve) {
  if (specifier.startsWith('./') || specifier.startsWith('../')) {
    const parentPath = context.parentURL ? path.dirname(fileURLToPath(context.parentURL)) : projectRoot;
    const candidate = path.resolve(parentPath, specifier);
    const resolved = await resolveWithExtensions(candidate);
    if (resolved) {
      return { url: resolved, shortCircuit: true };
    }
  }
  if (specifier.startsWith('@/')) {
    const candidate = path.join(projectRoot, specifier.slice(2));
    const resolved = await resolveWithExtensions(candidate);
    if (resolved) {
      return { url: resolved, shortCircuit: true };
    }
  }
  return defaultResolve(specifier, context, defaultResolve);
}

export async function load(url, context, defaultLoad) {
  if (!tsExtensions.some((ext) => url.endsWith(ext))) {
    return defaultLoad(url, context, defaultLoad);
  }
  const source = await readFile(fileURLToPath(url), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      jsx: ts.JsxEmit.Preserve,
      resolveJsonModule: true,
      allowImportingTsExtensions: true,
    },
    fileName: fileURLToPath(url),
  });
  return {
    format: 'module',
    source: outputText,
    shortCircuit: true,
  };
}
