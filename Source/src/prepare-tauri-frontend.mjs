import fs from 'node:fs';
import path from 'node:path';

const projectDir = path.resolve(process.cwd());
const outputDir = path.join(projectDir, 'tauri-dist');
const websiteDir = path.resolve(projectDir, '..', 'website');

function copyDirectory(sourceDir, targetDir) {
  fs.mkdirSync(targetDir, { recursive: true });

  for (const entry of fs.readdirSync(sourceDir, { withFileTypes: true })) {
    const sourcePath = path.join(sourceDir, entry.name);
    const targetPath = path.join(targetDir, entry.name);

    if (entry.isDirectory()) {
      copyDirectory(sourcePath, targetPath);
      continue;
    }

    fs.copyFileSync(sourcePath, targetPath);
  }
}

fs.rmSync(outputDir, { recursive: true, force: true });
fs.mkdirSync(outputDir, { recursive: true });

fs.copyFileSync(path.join(projectDir, 'index.html'), path.join(outputDir, 'index.html'));
copyDirectory(path.join(projectDir, 'assets'), path.join(outputDir, 'assets'));

if (fs.existsSync(websiteDir)) {
  copyDirectory(websiteDir, path.join(outputDir, 'website'));
}
