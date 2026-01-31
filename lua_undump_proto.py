#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lua_undump_proto.py
-------------------

Черновой парсер Proto для бинарных Lua-чанков игры, основанный на реверсе
`luaU_undump` + `loadFunction` из `libgame.so`.

Цель текущей версии:
  - честно разобрать заголовок чанка (\\x1bLua + версия/формат/типы);
  - пройти только ГЛАВНЫЙ Proto (без рекурсивного разбора дочерних функций);
  - вытащить список строковых констант из его таблицы k[].

Важно:
  - форматы чисел и varint'ов подобраны по дизасму, но это всё ещё PoC;
  - дочерние Proto и debug-секции пока намеренно игнорируются, чтобы
    не рисковать поломкой потока из‑за неточного скипа.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent
DUMPS_DIR = ROOT / "lua_dumps"


class ByteReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def need(self, n: int) -> None:
        if self.pos + n > len(self.data):
            raise ValueError(f"EOF: need {n} bytes at {self.pos}, size={len(self.data)}")

    def read_u8(self) -> int:
        self.need(1)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        self.need(n)
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def skip(self, n: int) -> None:
        self.need(n)
        self.pos += n

    def read_varint(self) -> int:
        """
        Varint-формат, который видно в loadFunction:
          value = 0
          do:
            b = read_u8()
            value = (b & 0x7F) | (value << 7)
          while (b & 0x80) == 0
        """
        value = 0
        while True:
            b = self.read_u8()
            value = (b & 0x7F) | (value << 7)
            if b & 0x80:
                break
        return value

    def read_lstring_varint(self) -> str:
        """
        Формат строк в loadFunction/loadStringN:
          - length varint (0 => NULL / пустая);
          - если length > 0: читаем (length-1) байт строки.

        По дизасму loadStringN:
          - varint -> v10;
          - v11 = v10 - 1;
          - luaZ_read(Z, buf, v11);
        Явного чтения нулевого терминатора из потока нет, поэтому
        в файле лежит только полезный payload без завершающего 0.
        """
        length = self.read_varint()
        if length == 0:
            return ""
        if length == 1:
            # пустая строка без payload
            return ""
        raw = self.read_bytes(length - 1)
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return repr(raw)


@dataclass
class ProtoSummary:
    """
    Краткая сводка по одному Proto.

    Храним:
      - глубину в дереве (0 = корневой Proto файла);
      - размеры кода / констант;
      - базовые поля заголовка;
      - строковые константы ТОЛЬКО этого Proto (для удобного поиска);
      - полную таблицу k[] (типы и значения) для точной привязки к W26‑коду.
    """
    depth: int
    line_defined: int
    last_line_defined: int
    num_params: int
    is_vararg: int
    max_stack: int
    code_size: int
    const_count: int
    string_consts: List[str] = field(default_factory=list)
    # Полная таблица k[]: типы и значения по индексам 0..const_count-1
    k_types: List[int] = field(default_factory=list)
    k_values: List[object] = field(default_factory=list)
    code_words: List[int] = field(default_factory=list)
    code_offset: int = 0


def parse_header_undump(data: bytes) -> ByteReader:
    """
    Заголовок в формате, соответствующем luaU_undump из libgame.so.

    По факту (см. lua_bytecode_inspect.py и дизасм luaU_undump) у них используется
    почти стандартный заголовок Lua 5.4, но без явных байтов "size_lua_integer /
    size_lua_number": вместо этого сразу идут сэмплы значений.

    Практически:
      0-3:  1B 4C 75 61   ("\\x1bLua")
      4:    версия (0x54)
      5:    формат (0)
      6-11: LUAC_DATA (6 байт)
      12:   sizeof(int)
      13:   sizeof(size_t)
      14:   sizeof(Instruction)      (в их дампах = 8)
      15-22: sample lua_Integer      (8 байт, значение 0x5678 и т.п.)
      23-30: sample lua_Number       (8 байт, значение 370.5)
      31.. : тело (Proto и т.д.)

    Нас в этом скрипте интересует только смещение до тела — 31 байт.
    """
    if len(data) < 31:
        raise ValueError("chunk too short for header")

    br = ByteReader(data)
    first = br.read_u8()
    if first != 0x1B:
        raise ValueError(f"unexpected first byte {first:#x}, not 0x1B")

    sig = br.read_bytes(3)
    if sig != b"Lua":
        raise ValueError("not a Lua chunk (no 'Lua' after 0x1B)")

    version = br.read_u8()
    fmt = br.read_u8()
    _luac_data = br.read_bytes(6)

    # Байты размеров нам здесь не критичны, просто скипаем их и два сэмпла:
    _size_int = br.read_u8()
    _size_size_t = br.read_u8()
    _size_instr = br.read_u8()

    # два сэмпла по 8 байт каждый
    br.skip(8)  # lua_Integer sample
    br.skip(8)  # lua_Number sample

    return br


def _find_proto0_offset(data: bytes) -> int:
    """
    Эвристический поиск начала корневого Proto:

    Идея:
      - начало Proto = место, где loadFunction впервые читает source-строку
        через loadStringN;
      - эта строка должна содержать '.lua' и/или 'combat';
      - сразу после неё должны идти разумные line_defined/last_line_defined,
        numparams/vararg/maxstack (без переполнений).

    Мы просто сканируем первые ~1 КБ файла в поисках такого места.
    Это избавляет от необходимости на 100% попадать в байтовую разметку
    luaU_undump, но даёт корректное выравнивание для Proto.
    """
    max_scan = min(len(data), 2048)

    # 1) Быстрая эвристика по строкам (если source содержит '.lua')
    for off in range(max_scan):
        br = ByteReader(data)
        br.pos = off
        try:
            s = br.read_lstring_varint()
        except ValueError:
            continue
        if not s or ".lua" not in s:
            continue
        # Быстрая проверка нескольких полей Proto
        try:
            ld = br.read_varint()
            lld = br.read_varint()
            num_params = br.read_u8()
            _ = br.read_u8()  # is_vararg
            max_stack = br.read_u8()
        except ValueError:
            continue
        if ld > 10_000_000 or lld > 10_000_000:
            continue
        if num_params > 64 or max_stack > 255:
            continue
        return off

    # 2) Брутфорс: пробуем полностью распарсить Proto с разных смещений
    #    и ищем первое место, где parse_proto проходит без EOF и даёт
    #    разумные размеры code/const.
    for off in range(max_scan):
        br = ByteReader(data)
        br.pos = off
        try:
            proto = parse_proto(br, _depth=1)  # depth=1, чтобы не спамить debug
        except Exception:
            continue
        if proto.code_size <= 0 or proto.code_size > 200_000:
            continue
        if proto.const_count < 0 or proto.const_count > 200_000:
            continue
        return off

    raise ValueError("не удалось найти начало корневого Proto (ни по строкам, ни по брутфорсу)")


def parse_proto(
    br: ByteReader,
    _depth: int = 0,
    summaries: Optional[List[ProtoSummary]] = None,
) -> ProtoSummary:
    """
    Разбор ОДНОГО Proto по реальной схеме из loadFunction, с полным
    воспроизведением порядка чтений из ZIO:

      - source (строка / NULL через loadStringN);
      - два varint'а (line_defined, last_line_defined);
      - три байта (numparams, is_vararg, maxstack);
      - varint nCode + блок code[] (4 * nCode байт);
      - varint nConst + константы k[];
      - varint nUpvalues + описатели upvalues (3 байта на upvalue);
      - varint nProto + рекурсивные Proto;
      - varint nLineInfo + байты lineinfo;
      - varint nLocVars + по два varint'а на locvar;
      - varint nUpValueNames + (строка + 2 varint'а) на upvalue-name;
      - varint extraFlag + при ненуле: по строке на каждый upvalue.

    В ProtoSummary складываем только данные ТЕКУЩЕГО Proto
    (строки дочерних не подмешиваем, но сами дочерние честно парсим,
    чтобы не ломать поток).
    """
    debug = _depth == 0

    # source (строка или пусто), но нам она не критична
    _source = br.read_lstring_varint()
    if debug:
        print(f"[DBG] depth={_depth} after source, pos={br.pos}")

    line_defined = br.read_varint()
    last_line_defined = br.read_varint()
    if debug:
        print(
            f"[DBG] depth={_depth} lines {line_defined}-{last_line_defined}, pos={br.pos}"
        )

    num_params = br.read_u8()
    is_vararg = br.read_u8()
    max_stack = br.read_u8()
    if debug:
        print(
            f"[DBG] depth={_depth} header np={num_params} vararg={is_vararg} maxstack={max_stack}, pos={br.pos}"
        )

    code_size = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} code_size={code_size}, pos={br.pos}")
    # читаем сами инструкции (4 байта каждая) как поток W26-слов
    instr_size = 4
    code_offset = br.pos
    code_bytes = br.read_bytes(code_size * instr_size)
    code_words = list(struct.unpack(f"<{code_size}I", code_bytes)) if code_size > 0 else []
    if debug:
        print(f"[DBG] depth={_depth} after code[], pos={br.pos}")

    const_count = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} const_count={const_count}, pos={br.pos}")
    string_consts: List[str] = []
    k_types: List[int] = []
    k_values: List[object] = []

    for _ in range(const_count):
        t = br.read_u8()
        k_types.append(t)
        # По типам констант ориентируемся на luaK_codek / luaU_undump:
        #   0  = nil
        #   1  = boolean
        #   3  = integer (lua_Integer, 8 байт)
        #   4  = string (short/long)
        #   19 = float (lua_Number, 8 байт)
        #   20 = long string
        if t == 0:
            # NIL
            k_values.append(None)
        elif t == 1:
            # boolean
            # В их билде по дизасму для case 1/17 НЕТ дополнительных чтений
            # (в отличие от классического Lua, где здесь читается 1 байт).
            # Чтобы не ломать поток, храним просто логический маркер True.
            k_values.append(True)
        elif t == 3:
            # integer: 8 байт lua_Integer (LE, знаковый)
            raw = br.read_bytes(8)
            (ival,) = struct.unpack("<q", raw)
            k_values.append(ival)
        elif t == 19:
            # float: 8 байт lua_Number (LE, double)
            raw = br.read_bytes(8)
            (fval,) = struct.unpack("<d", raw)
            k_values.append(fval)
        elif t == 4 or t == 20:
            s = br.read_lstring_varint()
            string_consts.append(s)
            k_values.append(s)
        else:
            # прочие типы (lightuserdata и т.п.) в их билде почти не используются;
            # для сохранения потока просто не читаем дополнительных байт и
            # помечаем значение как None.
            # Если такие типы встретятся, при необходимости можно будет доработать.
            k_values.append(None)

    # На этом этапе у нас уже есть всё, чтобы сформировать краткую сводку
    # по ТЕКУЩЕМУ Proto (до чтения upvalues / debug-данных).
    summary = ProtoSummary(
        depth=_depth,
        line_defined=line_defined,
        last_line_defined=last_line_defined,
        num_params=num_params,
        is_vararg=is_vararg,
        max_stack=max_stack,
        code_size=code_size,
        const_count=const_count,
        string_consts=string_consts,
        k_types=k_types,
        k_values=k_values,
        code_words=code_words,
        code_offset=code_offset,
    )
    if summaries is not None:
        summaries.append(summary)

    # ----- Upvalues (описатели) -----
    # Varint → количество upvalues, затем по 3 байта на каждый:
    #   instack, idx, kind
    n_upvalues = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} n_upvalues={n_upvalues}, pos={br.pos}")
    for _ in range(n_upvalues):
        # instack, idx, kind — по одному байту каждый
        br.read_u8()
        br.read_u8()
        br.read_u8()

    # ----- Вложенные Proto -----
    # Varint → nProto, далее на каждый рекурсивно вызывается loadFunction.
    # Нам пока достаточно «пройти» их, не смешивая строки с верхним Proto.
    n_protos = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} n_protos={n_protos}, pos={br.pos}")
    for _ in range(n_protos):
        # Рекурсивный разбор дочернего Proto; результат нам может пригодиться
        # только в summaries (для верхнего вызова), поэтому просто передаём
        # тот же аккумулятор.
        _child = parse_proto(br, _depth + 1, summaries=summaries)

    # ----- lineinfo -----
    n_lineinfo = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} n_lineinfo={n_lineinfo}, pos={br.pos}")
    if n_lineinfo:
        br.skip(n_lineinfo)

    # ----- locvars -----
    # Varint → nLocVars, затем по два varint'а на запись
    # (startpc, endpc / или аналогичные служебные поля).
    n_locvars = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} n_locvars={n_locvars}, pos={br.pos}")
    for _ in range(n_locvars):
        _start = br.read_varint()
        _end = br.read_varint()
        # значения нам не нужны, важен только корректный скип

    # ----- upvalue names -----
    # Varint → nUpValueNames, затем на каждый:
    #   name = loadStringN();
    #   два varint'а (pc-диапазон или аналогичные служебные значения).
    n_upvalue_names = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} n_upvalue_names={n_upvalue_names}, pos={br.pos}")
    for _ in range(n_upvalue_names):
        _name = br.read_lstring_varint()
        _a = br.read_varint()
        _b = br.read_varint()

    # ----- extra strings для upvalues -----
    # Последний varint (v143 в дизасме). Если он ненулевой — для каждого
    # upvalue читается ещё одна строка через loadStringN и кладётся в
    # upvalues[].name. Для нас это чисто служебный скип.
    extra_flag = br.read_varint()
    if debug:
        print(f"[DBG] depth={_depth} extra_flag={extra_flag}, pos={br.pos}")
    if extra_flag:
        for _ in range(n_upvalues):
            _ = br.read_lstring_varint()

    return summary


def inspect_file(path: Path) -> None:
    data = path.read_bytes()
    print("=" * 80)
    print(f"[FILE] {path.name}  size={len(data)} bytes")

    try:
        # Для совместимости проверим сигнатуру/заголовок, но позицию Proto
        # дальше будем искать эвристически.
        _hdr_br = parse_header_undump(data)
    except Exception as e:
        print(f"[!] header parse failed: {e}")
        return

    # Попробуем найти смещение, с которого начинается source-строка корневого Proto.
    try:
        proto_off = _find_proto0_offset(data)
    except Exception as e:
        print(f"[!] failed to locate Proto0 start: {e}")
        return

    br = ByteReader(data)
    br.pos = proto_off

    # Для отладки покажем первые байты вокруг найденного Proto
    preview_bytes = br.data[br.pos : br.pos + 16]
    preview = " ".join(f"{b:02X}" for b in preview_bytes)
    print(f"[HDR] proto0@{proto_off}: {preview}")

    summaries: List[ProtoSummary] = []
    try:
        proto0 = parse_proto(br, _depth=0, summaries=summaries)
    except Exception as e:
        print(f"[!] top Proto parse failed: {e}")
        return

    if not summaries:
        print("[!] parse_proto did not produce any summaries")
        return

    # Корневой Proto — первый в списке
    proto = summaries[0]

    print(
        f"[PROTO0] line={proto.line_defined}-{proto.last_line_defined} "
        f"params={proto.num_params} vararg={proto.is_vararg} "
        f"maxstack={proto.max_stack} code={proto.code_size} consts={proto.const_count}"
    )

    uniq = sorted(set(proto.string_consts))
    print(f"[STR] top-level string consts: {len(uniq)}")
    for s in uniq:
        print(f"       {s!r}")

    # Дополнительно выведем краткое дерево Proto с интересными строками
    interesting_keywords = (
        "Damage",
        "damage",
        "HpDelta",
        "RealDamage",
        "GetDamageValue",
        "OnDamage",
        "HandleWithHpChangeInfo",
        "ConsumeHitInfo",
        "DamageData",
        "hitInfo",
    )
    print("--- Proto tree (with damage-related strings) ---")
    for idx, ps in enumerate(summaries):
        hits = sorted(
            {s for s in ps.string_consts if any(k in s for k in interesting_keywords)}
        )
        if not hits:
            continue
        indent = "  " * ps.depth
        print(
            f"{indent}- P{idx}: depth={ps.depth} "
            f"code={ps.code_size} consts={ps.const_count} "
            f"lines={ps.line_defined}-{ps.last_line_defined}"
        )
        for s in hits:
            print(f"{indent}    {s!r}")

    # Попробуем сопоставить Proto с глобальным потоком W26 из *.low32.bin
    try:
        map_protos_to_w26(path, summaries)
    except Exception as e:
        print(f"[!] W26 mapping failed: {e}")


def map_protos_to_w26(chunk_path: Path, summaries: List[ProtoSummary]) -> None:
    """
    Сопоставление локальных code[] каждого Proto с глобальным W26-потоком
    из lua_dumps_normalized/*.low32.bin.

    Предполагаем, что *.low32.bin уже построен (lua_bytecode_entropy_normalize.py)
    и представляет собой массив W26-слов в LE.
    """
    norm_dir = ROOT / "lua_dumps_normalized"
    norm_path = norm_dir / (chunk_path.name + ".low32.bin")
    if not norm_path.is_file():
        print(f"[W26] normalized stream not found: {norm_path.name}")
        return

    data = norm_path.read_bytes()
    if len(data) % 4 != 0:
        data = data[: len(data) - (len(data) % 4)]
    total = len(data) // 4
    global_words = list(struct.unpack(f"<{total}I", data))

    print(f"[W26] mapping against {norm_path.name} ({total} words)")

    def find_subseq(seq: List[int]) -> Optional[int]:
        if not seq:
            return None
        n = len(seq)
        limit = len(global_words) - n + 1
        for i in range(limit):
            if global_words[i] != seq[0]:
                continue
            if global_words[i : i + n] == seq:
                return i
        return None

    interesting_keywords = (
        "Damage",
        "damage",
        "HpDelta",
        "RealDamage",
        "GetDamageValue",
        "OnDamage",
        "HandleWithHpChangeInfo",
        "ConsumeHitInfo",
        "DamageData",
        "hitInfo",
        "hitDamage",
    )

    print("[W26] Proto → PC ranges (for damage-related protos)")
    for idx, ps in enumerate(summaries):
        if not ps.code_words:
            continue
        hits = {s for s in ps.string_consts if any(k in s for k in interesting_keywords)}
        if not hits:
            continue
        start_pc = find_subseq(ps.code_words)
        if start_pc is None:
            continue
        end_pc = start_pc + ps.code_size
        indent = "  " * ps.depth
        print(
            f"{indent}- P{idx}: depth={ps.depth} code={ps.code_size} "
            f"PC=[{start_pc},{end_pc}) hits={sorted(hits)}"
        )


def main() -> None:
    if not DUMPS_DIR.is_dir():
        print(f"[!] Директория с дампами не найдена: {DUMPS_DIR}")
        return

    targets: List[Path] = []
    for p in sorted(DUMPS_DIR.glob("*.lua.bin")):
        targets.append(p)

    if not targets:
        print("[!] В lua_dumps/ нет *.lua.bin")
        return

    # Для начала ограничимся ключевыми боевыми файлами.
    key_names = (
        "combat_api_damageFunc.lua.bin",
        "combat_system_damageSystem.lua.bin",
    )
    selected: List[Path] = []
    for p in targets:
        if any(p.name.endswith(k) for k in key_names):
            selected.append(p)

    if not selected:
        selected = targets[:4]

    print(f"[*] Буду разбирать {len(selected)} файлов (Proto верхнего уровня):")
    for p in selected:
        print(f"    - {p.name}")
    print()

    for p in selected:
        inspect_file(p)


if __name__ == "__main__":
    main()


