import { existsSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const projectRoot = resolvePath(dirname(fileURLToPath(import.meta.url)), '..');

function resolveWithExtensions(specifierPath) {
  const attempts = [specifierPath];
  const exts = ['.ts', '.tsx', '.js', '.mjs', '.cjs'];
  for (const ext of exts) {
    attempts.push(`${specifierPath}${ext}`);
  }
  const dir = existsSync(specifierPath) && statSync(specifierPath).isDirectory();
  if (dir) {
    for (const ext of exts) {
      attempts.push(join(specifierPath, `index${ext}`));
    }
  }
  for (const candidate of attempts) {
    if (existsSync(candidate) && statSync(candidate).isFile()) {
      return candidate;
    }
  }
  return specifierPath;
}

export async function resolve(specifier, context, defaultResolve) {
  if (specifier.startsWith('node:')) {
    return defaultResolve(specifier, context, defaultResolve);
  }

  if (specifier.startsWith('@/')) {
    const absolute = resolveWithExtensions(resolvePath(projectRoot, specifier.slice(2)));
    const resolved = pathToFileURL(absolute).href;
    return { url: resolved, format: 'module', shortCircuit: true };
  }

  if (specifier === 'next/server') {
    const absolute = resolveWithExtensions(resolvePath(projectRoot, 'tests/stubs/next-server'));
    const resolved = pathToFileURL(absolute).href;
    return { url: resolved, format: 'module', shortCircuit: true };
  }

  if (specifier.startsWith('./') || specifier.startsWith('../') || specifier.startsWith('/')) {
    const parentURL = context.parentURL ? fileURLToPath(context.parentURL) : projectRoot;
    const baseDir = specifier.startsWith('.') ? dirname(parentURL) : projectRoot;
    const withoutLeadingSlash = specifier.startsWith('/') ? specifier.slice(1) : specifier;
    const targetPath = specifier.startsWith('.')
      ? resolvePath(baseDir, specifier)
      : resolvePath(projectRoot, withoutLeadingSlash);
    const absolute = resolveWithExtensions(targetPath);
    if (existsSync(absolute)) {
      const resolved = pathToFileURL(absolute).href;
      return { url: resolved, format: 'module', shortCircuit: true };
    }
  }

  return defaultResolve(specifier, context, defaultResolve);
}

export async function load(url, context, defaultLoad) {
  if (url.endsWith('.ts') || url.endsWith('.tsx')) {
    const source = await readFile(new URL(url));
    const { outputText } = ts.transpileModule(source.toString(), {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.NodeNext,
        target: ts.ScriptTarget.ES2022,
        esModuleInterop: true,
        jsx: ts.JsxEmit.Preserve,
      },
      fileName: fileURLToPath(url),
    });
    return {
      format: 'module',
      source: outputText,
      shortCircuit: true,
    };
  }
  return defaultLoad(url, context, defaultLoad);
}
