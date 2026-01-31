#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lua_disasm_from_proto.py
------------------------

Дизассемблер W26-кода конкретных Proto прямо из *.lua.bin, без .low32.bin.

Использует:
  - lua_undump_proto.parse_proto / ProtoSummary, чтобы разобрать дерево Proto;
  - локальные code_words (массив 32-битных W26-слов) для каждого Proto;
  - ту же схемy бит, что и lua_disasm_full.py (op/A/F/B/C + производные).

Назначение в тяжёлой ветке:
  - удобно дизассемблировать только интересные Proto по строкам:
      * 'GetDamageValue', 'HandleWithHpChangeInfo', 'OnDamage',
        'DamageData', 'hitDamage', 'ConsumeHitInfo' и т.п.;
  - работать сразу с реальным Proto-кодом, а не эвристическим .low32.bin.
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import lua_disasm_full as w26_full
import lua_undump_proto as undump


ROOT = Path(__file__).resolve().parent
DUMPS_DIR = ROOT / "lua_dumps"


@dataclass
class DecodedInstr:
    pc: int
    word: int
    op: int
    A: int
    F: int
    B: int
    C: int
    Bx17: int
    sBx17: int
    off_12_ffff8: int
    off_13_7fffc: int
    off_20_ff0: int

    @property
    def op_name(self) -> str:
        """
        Человекочитаемое имя опкода по общей карте OP_NAMES.
        Для неизвестных опкодов выводим заглушку OP_XX.
        """
        name = w26_full.OP_NAMES.get(self.op)
        if name is None:
            return f"OP_{self.op:02d}"
        return name


def decode_word(pc: int, word: int) -> DecodedInstr:
    """
    Декодирование одного 32-битного W26-слова по схеме из lua_disasm_full.py.
    """
    op = word & 0x7F
    A = (word >> 7) & 0xFF
    F = (word >> 15) & 0x1
    B = (word >> 16) & 0xFF
    C = (word >> 24) & 0xFF

    Bx17 = (F << 16) | (B << 8) | C
    sBx17 = Bx17 - 0x10000

    off_12_ffff8 = (word >> 12) & 0xFFFF8
    off_13_7fffc = (word >> 13) & 0x7FFFC
    off_20_ff0 = (word >> 20) & 0xFF0

    return DecodedInstr(
        pc=pc,
        word=word,
        op=op,
        A=A,
        F=F,
        B=B,
        C=C,
        Bx17=Bx17,
        sBx17=sBx17,
        off_12_ffff8=off_12_ffff8,
        off_13_7fffc=off_13_7fffc,
        off_20_ff0=off_20_ff0,
    )


def resolve_chunk(path_str: str) -> Path:
    p = Path(path_str)
    if p.is_file():
        return p
    cand = DUMPS_DIR / p.name
    if cand.is_file():
        return cand
    raise SystemExit(f"[!] Lua-чанк не найден: {p} или {cand}")


def choose_proto(
    summaries: List[undump.ProtoSummary],
    proto_index: Optional[int],
    substr: Optional[str],
) -> Tuple[int, undump.ProtoSummary]:
    """
    Выбор Proto:
      - если задан --proto-index, берём его;
      - иначе, если задан --match, ищем первый Proto, где какая-либо строка
        содержит подстроку (регистрочувствительно);
      - иначе берём корневой (0).
    """
    if proto_index is not None:
        if not (0 <= proto_index < len(summaries)):
            raise SystemExit(
                f"[!] --proto-index {proto_index} вне диапазона (0..{len(summaries)-1})"
            )
        return proto_index, summaries[proto_index]

    if substr:
        for idx, ps in enumerate(summaries):
            for s in ps.string_consts:
                if substr in s:
                    return idx, ps
        raise SystemExit(f"[!] Не найден Proto со строками, содержащими {substr!r}")

    # по умолчанию — корневой
    return 0, summaries[0]


def parse_chunk_protos(path: Path) -> List[undump.ProtoSummary]:
    data = path.read_bytes()
    # проверим, что это действительно Lua-чанк (сигнатура и базовый header)
    undump.parse_header_undump(data)

    # найдём смещение корневого Proto и распарсим всё дерево в summaries
    proto_off = undump._find_proto0_offset(data)  # type: ignore[attr-defined]
    br = undump.ByteReader(data)
    br.pos = proto_off

    summaries: List[undump.ProtoSummary] = []
    undump.parse_proto(br, _depth=0, summaries=summaries)
    if not summaries:
        raise SystemExit("[!] parse_proto не вернул ни одного ProtoSummary")
    return summaries


def disasm_proto(
    code_words: List[int],
    limit: Optional[int] = None,
    pc_range: Optional[Tuple[int, Optional[int]]] = None,
    op_filter: Optional[int] = None,
    proto: Optional[undump.ProtoSummary] = None,
) -> None:
    total = len(code_words)
    print(f"[DISASM] Proto code_size={total}")

    start = 0
    end: Optional[int] = None
    if pc_range is not None:
        start, end = pc_range

    shown = 0
    for pc in range(total):
        if pc < start:
            continue
        if end is not None and pc >= end:
            break
        if limit is not None and shown >= limit:
            print(f"... обрезано на {limit} инструкциях ...")
            break

        word = code_words[pc]
        d = decode_word(pc, word)
        if op_filter is not None and d.op != op_filter:
            continue

        # Дополнительная аннотация по k[] (если у Proto есть полная таблица констант)
        k_comment = ""
        if proto is not None and proto.const_count and proto.k_values:
            # HELPERS: безопасное получение значения из k[] по индексу
            def k_at(idx: int) -> Optional[object]:
                if 0 <= idx < len(proto.k_values):
                    return proto.k_values[idx]
                return None

            # LOADK A, Bx17 → индекс константы, судя по дизасму, кладётся в B (C=0)
            if d.op_name == "LOADK":
                k_idx = d.B
                v = k_at(k_idx)
                if v is not None:
                    k_comment = f"  ; LOADK k[{k_idx}]={v!r}"

            # Для табличных операций предполагаем, что C часто указывает на строковую константу-ключ.
            elif d.op_name in {
                "GETTABUP",
                "GETTABLE",
                "GETI",
                "GETFIELD",
                "SETTABUP",
                "SETTABLE",
                "SETI",
                "SETFIELD",
            }:
                k_idx = d.C
                v = k_at(k_idx)
                if v is not None:
                    k_comment = f"  ; k[{k_idx}]={v!r}"

        print(
            f"{d.pc:5d}: 0x{d.word:08X}  "
            f"op={d.op:3d}({d.op_name:<10})  "
            f"A={d.A:3d} F={d.F} B={d.B:3d} C={d.C:3d}  "
            f"Bx17={d.Bx17:5d} sBx17={d.sBx17:6d}  "
            f"off12=0x{d.off_12_ffff8:05X} off13=0x{d.off_13_7fffc:05X} off20=0x{d.off_20_ff0:04X}"
            f"{k_comment}"
        )
        shown += 1


def parse_range(range_str: str) -> Tuple[int, Optional[int]]:
    if ":" not in range_str:
        start = int(range_str)
        return start, None
    start_s, end_s = range_str.split(":", 1)
    start = int(start_s) if start_s else 0
    end = int(end_s) if end_s else None
    return start, end


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Дизассемблер W26-кода отдельных Proto прямо из *.lua.bin",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "chunk",
        help="Путь к *.lua.bin или просто имя файла (будет искаться в lua_dumps/)",
    )
    p.add_argument(
        "--proto-index",
        type=int,
        default=None,
        help="Индекс Proto в дереве (как в выводе lua_undump_proto.py)",
    )
    p.add_argument(
        "--match",
        type=str,
        default=None,
        help="Строка/подстрока для поиска по string_consts Proto (например, GetDamageValue)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Ограничить вывод первыми N инструкциями",
    )
    p.add_argument(
        "--range",
        type=str,
        default=None,
        help="Диапазон PC в формате START или START:END (END не включительно)",
    )
    p.add_argument(
        "--dump-consts",
        action="store_true",
        help="Вывести таблицу констант k[] выбранного Proto и завершить без дизасма",
    )
    p.add_argument(
        "--op",
        type=int,
        default=None,
        help="Фильтровать по конкретному op (0..127)",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.op is not None and not (0 <= args.op <= 127):
        print("[!] --op должен быть в диапазоне 0..127")
        return 1

    chunk_path = resolve_chunk(args.chunk)
    summaries = parse_chunk_protos(chunk_path)
    idx, ps = choose_proto(summaries, args.proto_index, args.match)

    print(
        f"[INFO] chunk={chunk_path.name}, P{idx}: "
        f"depth={ps.depth}, code={ps.code_size}, consts={ps.const_count}, "
        f"lines={ps.line_defined}-{ps.last_line_defined}"
    )

    if not ps.code_words:
        print("[!] У выбранного Proto нет кода (code_size=0)")
        return 1

    if args.dump_consts:
        print(f"[CONST] Proto P{idx}: const_count={ps.const_count}")
        type_names = {
            0: "NIL",
            1: "BOOLEAN",
            3: "INTEGER",
            4: "STRING",
            19: "FLOAT",
            20: "LSTRING",
        }
        for i in range(ps.const_count):
            t = ps.k_types[i] if i < len(ps.k_types) else -1
            v = ps.k_values[i] if i < len(ps.k_values) else None
            t_name = type_names.get(t, f"TYPE_{t}")
            print(f"  k[{i:3d}]: {t_name:7}  {v!r}")
        return 0

    pc_range: Optional[Tuple[int, Optional[int]]] = None
    if args.range:
        try:
            pc_range = parse_range(args.range)
        except ValueError:
            print("[!] Некорректный формат диапазона для --range")
            return 1

    disasm_proto(
        code_words=ps.code_words,
        limit=args.limit,
        pc_range=pc_range,
        op_filter=args.op,
        proto=ps,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



