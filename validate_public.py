"""Validate the consultation-only ZIP before deploying GitHub Pages.

This file is public deployment plumbing, not a financial engine. Its explicit
allowlist prevents accidentally deploying AWW-reprise.zip or aww-source.zip.
Hashes detect incomplete transfers; they are not a digital signature.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

SHELL = {'index.html', 'viewer.js', 'viewer.css', 'navigation.js', 'sw.js',
         'catalog.json', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png',
         'apple-touch-icon.png', '.nojekyll'}
FORBIDDEN = re.compile(rb'AWW_STRATEGY|AWW_PROPHET|AWW_EARLY|AWW_DATA|'
                       rb'function\s+indexSignals|function\s+cycleMetrics|'
                       rb'function\s+dcaIndications|createStepper|metricsProvider|'
                       rb'sellMemory|buyMemory|sourceMappingURL|'
                       rb'github_pat_[A-Za-z0-9_]{20}|gh[pousr]_[A-Za-z0-9]{20}|'
                       rb'-----BEGIN .*PRIVATE KEY-----')


def validate(archive):
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)) or len(names) > 1000:
            raise ValueError('Archive dupliquée ou trop grande')
        if sum(i.file_size for i in bundle.infolist()) > 200_000_000:
            raise ValueError('Archive décompressée trop grande')
        for name in names:
            if name not in SHELL | {'manifest-public.json'} and not re.fullmatch(r'data/[a-f0-9]{64}\.json', name):
                raise ValueError('Fichier interdit : ' + name)
        files = {name: bundle.read(name) for name in names}
    manifest = json.loads(files['manifest-public.json'])
    if set(manifest) != {'schemaVersion', 'files'} or manifest['schemaVersion'] != 1 or set(files) != set(manifest['files']) | {'manifest-public.json'}:
        raise ValueError('Manifeste incomplet')
    if FORBIDDEN.search(files['manifest-public.json']):
        raise ValueError('Manifeste privé interdit')
    if not SHELL <= set(files):
        raise ValueError('Lecteur incomplet')
    for name, entry in manifest['files'].items():
        if set(entry) != {'bytes', 'sha256'}:
            raise ValueError('Entrée de manifeste incorrecte')
        raw = files[name]
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != entry['bytes'] or digest != entry['sha256']:
            raise ValueError('Empreinte incorrecte : ' + name)
        if not name.endswith('.png') and FORBIDDEN.search(raw):
            raise ValueError('Contenu privé interdit : ' + name)
        if name.startswith('data/') and name != 'data/' + digest + '.json':
            raise ValueError('Nom de données incorrect')
    catalog = json.loads(files['catalog.json'])
    # Six fixed cash views (aggressive BAM + TP), nine H4 directions. Previously 21.
    # Also read the previous 21-view archive for coverage checks during migration.
    if catalog['schemaVersion'] != 1 or len(catalog['views']) not in (15, 21):
        raise ValueError('Catalogue incorrect')
    for view in catalog['views']:
        for name in [view['calendar'], *view['panels']]:
            if not re.fullmatch(r'data/[a-f0-9]{64}\.json', name) or name not in files:
                raise ValueError('Résultat manquant')
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive')
    parser.add_argument('--extract', type=Path)
    args = parser.parse_args()
    files = validate(args.archive)
    if args.extract:
        target = args.extract.resolve()
        if target.exists() and any(target.iterdir()):
            raise ValueError('Choisir un dossier de sortie vide')
        for name, raw in files.items():
            dest = target / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
    print(json.dumps({'files': len(files), 'bytes': sum(map(len, files.values())), 'valid': True}))


if __name__ == '__main__':
    main()
