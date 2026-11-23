#!/usr/bin/env python3
"""scan.py — проверка C64-демок (d64 / zip с d64) на пригодность к переводу в EasyFlash CRT.

  python3 scan.py ДЕМКИ...            быстрый скан (статика + эмуляция бутера), ~5-20 с на демку
  python3 scan.py --convert ДЕМКИ...  для совместимых: снять файлы, собрать CRT и проверить его
  -o папка                            куда класть CRT и отчёт (по умолчанию ./out)

ДЕМКИ — zip-архивы, d64-файлы или папки с ними. Стороны одной демки группируются
по zip-архиву или по общему имени файла (…-a.d64, …-b.d64 / side1, side2 …).
"""
import sys, os, re, zipfile, tempfile, argparse, time, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from d64 import D64, SPT
import bitfire as BF

D64_SIZES = {174848, 175531, 196608, 197376, 205312, 206114}
LOADER_WORDS = [b'bitfire', b'krill', b'spindle', b'sparkle', b'bongo', b'cruncher', b'exomizer',
                b'bitnax', b'dali', b'tinycrunch', b'loader', b'trackmo']

def collect(args, tmp):
    groups = []   # (name, [paths])
    loose = []
    def add_zip(p):
        z = zipfile.ZipFile(p); paths = []
        for n in sorted(z.namelist()):
            if n.lower().endswith('.d64'):
                dst = os.path.join(tmp, '%d_%s' % (len(groups), os.path.basename(n)))
                open(dst, 'wb').write(z.read(n)); paths.append(dst)
        if paths: groups.append((os.path.splitext(os.path.basename(p))[0], paths))
        else: groups.append((os.path.basename(p), []))
    for a in args:
        if os.path.isdir(a):
            for f in sorted(os.listdir(a)):
                q = os.path.join(a, f)
                if f.lower().endswith('.zip'): add_zip(q)
                elif f.lower().endswith('.d64'): loose.append(q)
        elif a.lower().endswith('.zip'): add_zip(a)
        elif a.lower().endswith('.d64'): loose.append(a)
    by = {}
    for p in loose:
        b = os.path.splitext(os.path.basename(p))[0]
        key = re.sub(r'([ _\-]*(side|disk|disc|s|d)?[ _\-]*([0-9]|[a-dA-D]))$', '', b, flags=re.I) or b
        by.setdefault(key, []).append(p)
    for k, v in by.items(): groups.append((k, sorted(v)))
    return groups

def bn(p):
    return re.sub(r'^\d+_', '', os.path.basename(p))

def static_info(path):
    d = D64(path)
    info = {'size': len(d.d), 'files': 0, 'file_blocks': 0}
    tracks = 40 if len(d.d) >= 196608 else 35
    owned = set()
    try:
        for e in d.dir():
            if e[0] & 7 in (1, 2, 3, 4):
                info['files'] += 1
                try:
                    _, ch = d.file(e[1], e[2]); owned |= set(ch); info['file_blocks'] += len(ch)
                except Exception: pass
    except Exception:
        info['dir_broken'] = True
    nz = 0; raw = 0
    for t in range(1, tracks + 1):
        for s in range(SPT[t-1]):
            if any(d.sec(t, s)):
                nz += 1
                if (t, s) not in owned and t != 18: raw += 1
    info.update(tracks=tracks, used=nz, raw=raw)
    low = d.d.lower()
    info['words'] = sorted({w.decode() for w in LOADER_WORDS if w in low})
    info['bitfire'] = BF.bitfire_dir(d)
    return info

def scan_group(name, paths, args, log):
    rep = {'name': name, 'sides': len(paths)}
    if not paths:
        rep['verdict'] = '—'; rep['why'] = 'в архиве нет d64 (g64/d81/prg/crt не поддерживаются)'; return rep
    bad = [p for p in paths if os.path.getsize(p) not in D64_SIZES]
    if bad:
        rep['verdict'] = '—'; rep['why'] = 'нестандартный размер d64: ' + ', '.join(os.path.basename(p) for p in bad)
        return rep
    infos = [(p, static_info(p)) for p in paths]
    bfs = [(i['bitfire'][0], p, i['bitfire'][1]) for p, i in infos if i['bitfire']]
    other = [p for p, i in infos if not i['bitfire']]
    rep['raw'] = sum(i['raw'] for _, i in infos)
    rep['files'] = sum(i['files'] for _, i in infos)
    rep['words'] = sorted({w for _, i in infos for w in i['words']})
    rep['notes'] = []
    if bfs and other:
        rep['notes'].append('не Bitfire (отдельные программы?): ' + ', '.join(os.path.basename(p) for p in other))
    # variants: several disks with the same side id
    sides = {}
    for sid, p, e in sorted(bfs, key=lambda x: (x[0], len(os.path.basename(x[1])), x[1])):
        sides.setdefault(sid, []).append((sid, p, e))
    if bfs:
        boot_path = sides[min(sides)][0][1]
    else:
        boot_path = paths[0]
    t0 = time.time()
    r = BF.emulate_boot(boot_path)
    rep['boot_time'] = round(time.time() - t0, 1)
    if getattr(r, 'error', None):
        rep['verdict'] = '❓'; rep['why'] = r.error; return rep
    rep['boot'] = r.boot_name.decode('latin-1', 'replace')
    rep['notes'] += list(r.notes)
    if r.result[0] == 'kernal':
        rep['notes'].append('эмуляция остановилась на вызове KERNAL $%04X' % r.result[1])
    elif r.result[0] == 'maxc':
        rep['notes'].append('эмуляция бутера не завершилась за 40 млн тактов (PC=$%04X)' % r.result[1])
    elif r.result[0] == 'error':
        rep['notes'].append('эмуляция: ' + r.result[1])
    if r.loads:
        rep['notes'].append('KERNAL LOAD: ' + ', '.join((n.decode('latin-1') or '?') for n, a in r.loads[:6]))
    if not r.drive_used:
        if rep['raw'] > 40:
            rep['verdict'] = '❓'
            rep['why'] = ('много секторов вне файлов (%d), но код в дисковод в эмуляции не заливался — '
                          'нестандартный старт или защита' % rep['raw'])
        else:
            rep['verdict'] = 'ℹ️'
            rep['why'] = 'своего кода в дисководе не видно, файлы обычные' + \
                         (' — одну сторону KFF обычно грузит и так' if len(paths) == 1 else
                          ' — но дисков %d' % len(paths))
        return rep
    fp = BF.drive_fingerprint(r)
    rep['drive_fp'] = fp
    if not bfs:
        rep['verdict'] = '❌'
        rep['why'] = 'свой загрузчик в дисководе (не Bitfire), отпечаток %s' % fp
        return rep
    try:
        a = BF.analyse_bitfire(r)
    except ValueError as ex:
        rep['verdict'] = '🟡'; rep['why'] = 'Bitfire, но ' + ex.args[0]
        return rep
    # sides: group by id, alternatives (e.g. digimax variants) become separate CRTs
    byid = {}
    for sid, p, ents in bfs: byid.setdefault(sid, []).append((p, ents))
    ids = sorted(byid)
    if ids != list(range(0xf0, 0xf0 + len(ids))):
        rep['verdict'] = '🟡'; rep['why'] = 'Bitfire совместимый, но стороны не подряд: ' + ' '.join('$%02X' % x for x in ids)
        return rep
    if len(ids) > 4:
        rep['verdict'] = '🟡'; rep['why'] = 'Bitfire совместимый, но сторон больше 4'; return rep
    for sid in ids:
        byid[sid].sort(key=lambda t: (len(os.path.basename(t[0])), t[0]))
        if len(byid[sid]) > 1:
            rep['notes'].append('сторона $%02X в вариантах: %s — будет CRT на каждый' % (
                sid, ', '.join(bn(p) for p, _ in byid[sid])))
        if not byid[sid][0][1]:
            rep['notes'].append('сторона $%02X без файлов Bitfire (%s)' % (sid, bn(byid[sid][0][0])))
    variants = [[]]
    for sid in ids:
        if len(byid[sid]) == 1: variants = [v + [(sid,) + byid[sid][0]] for v in variants]
        else: variants = [v + [(sid,) + alt] for v in variants for alt in byid[sid]]
    variants = variants[:4]
    main = variants[0]
    total = sum(n for _, _, ents in main for _, n in ents)
    if total > 63 * 16384 - 0x200:
        rep['verdict'] = '🟡'; rep['why'] = 'данные (%d КБ) не влезают в 1 МБ' % (total // 1024); return rep
    if not r.demo_started:
        rep['notes'].append('бутер в эмуляции не дошёл до первой части')
    pr = a['prof']
    rep['verdict'] = '✅'
    rep['why'] = 'Bitfire (резидент: send $%04X, poll $%04X, указатель $%02X): %d сторон, %d файлов, %d КБ' % (
        pr['send'], pr['poll'], pr['src'], len(ids), sum(len(e) for _, _, e in main), total // 1024)
    if args.convert:
        if not r.demo_started:
            rep['verdict'] = '🟡'; rep['why'] += '; конвертация пропущена (не найден старт демки)'; return rep
        import conv
        t0 = time.time(); crts = []; fails = []
        uniq = []
        for var in variants:
            for t in var:
                if t[1] not in [u[1] for u in uniq]: uniq.append(t)
        uniq.sort(key=lambda t: (t[1] != boot_path, t[0]))
        try:
            files = BF.harvest(r, pr, uniq, log=log)
        except ValueError as ex:
            rep['verdict'] = '🟡'; rep['why'] += '; не удалось снять файлы: ' + ex.args[0]; return rep
        boot_fresh = BF.emulate_boot(boot_path)
        for vi, var in enumerate(variants):
            try:
                fbs = [(sid, files[p]) for sid, p, ents in var]
                res0 = bytes(boot_fresh.boot_ram[0x200:0x400])
                log('  ищу переходы между сторонами и ожидания дисковода…')
                logic = BF.find_disk_logic(fbs, res0, pr, log=log)
                while len(fbs) > 1 and not fbs[-1][1] and logic['trans'].get(len(fbs) - 1) is None:
                    rep['notes'].append('сторона $%02X пустая и из демки не вызывается — не включена (это отдельный диск)' % fbs[-1][0])
                    fbs.pop()
                if vi == 0:
                    for k in range(1, len(fbs)):
                        c = logic['trans'].get(k)
                        if c is None: rep['notes'].append('переход на сторону $%02X в коде не найден' % fbs[k][0])
                        elif c < 0xf0: rep['notes'].append('переход на сторону $%02X — командой-плагином $%02X (считаю сменой диска)' % (fbs[k][0], c))
                    if logic['sites']:
                        rep['notes'].append('обезвреживается ожиданий дисковода: %d (%s)' % (len(logic['sites']), ', '.join('$%04X' % x for x in logic['sites'])))
                os.makedirs(args.out, exist_ok=True)
                tag = ''
                if len(variants) > 1:
                    alts = [os.path.splitext(bn(p))[0] for sid, p, _ in var if len(byid[sid]) > 1]
                    tag = ' (' + ', '.join(alts) + ')'
                out = os.path.join(args.out, re.sub(r'[\\/:*?"<>|]', '_', name + tag) + ' [EasyFlash].crt')
                rom, used = conv.build(out, a, fbs, (name + tag).upper()[:31], logic)
                log('  CRT%s собран, проверяю все загрузки…' % tag)
                ok, msg = conv.verify(rom, a, boot_fresh, fbs, log=log, logic=logic)
            except ValueError as ex:
                ok, msg, out = False, ex.args[0], None
            if ok: crts.append((out, msg))
            else:
                fails.append(msg)
                if out and os.path.exists(out): os.rename(out, out + '.FAILED')
        rep['convert_time'] = round(time.time() - t0)
        rep['notes'] = list(dict.fromkeys(rep['notes']))
        if crts and not fails:
            rep['verdict'] = '✅✅'; rep['why'] += '; CRT собран и проверен (%s)' % crts[0][1]; rep['crt'] = [c for c, _ in crts]
            if len(crts) > 1: rep['notes'].append('собрано CRT: %d' % len(crts))
        else:
            rep['verdict'] = '🟡'; rep['why'] += '; конвертация не прошла проверку: ' + '; '.join(fails)
    return rep

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('inputs', nargs='+')
    ap.add_argument('--convert', action='store_true')
    ap.add_argument('-o', '--out', default='out')
    args = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix='scan64_')
    groups = collect(args.inputs, tmp)
    reps = []
    for name, paths in groups:
        print('== %s (%d d64)' % (name, len(paths))); sys.stdout.flush()
        try:
            rep = scan_group(name, paths, args, log=lambda s: (print(s), sys.stdout.flush()))
        except Exception as ex:
            rep = {'name': name, 'verdict': '❓', 'why': 'ошибка сканера: %r' % ex}
        reps.append(rep)
        print('  %s %s' % (rep['verdict'], rep['why']))
        for n in rep.get('notes', []): print('     · ' + n)
        if rep.get('words'): print('     · строки на диске: ' + ', '.join(rep['words']))
        sys.stdout.flush()
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, 'scan_report.tsv'), 'w', encoding='utf-8') as f:
        f.write('демка\tсторон\tвердикт\tпричина\tотпечаток дисковода\tзаметки\n')
        for r in reps:
            f.write('\t'.join([r['name'], str(r.get('sides', '')), r['verdict'], r['why'],
                               r.get('drive_fp', ''), '; '.join(r.get('notes', []))]) + '\n')
    print('\nИтого:')
    for r in reps: print('  %-4s %s' % (r['verdict'], r['name']))
    print('Легенда: ✅✅ CRT готов и проверен · ✅ подходит · 🟡 Bitfire, нужна подгонка · '
          '❌ другой загрузчик · ℹ️ обычные файлы · ❓ не удалось определить')

if __name__ == '__main__':
    main()
