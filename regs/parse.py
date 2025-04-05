sections = open("gc_9_4_3_offset.h").read().split("#endif")[0].strip().split("// addressBlock: ")
regs = {}
secs = {}
for s in sections[1:]:
  ss = s.strip().split("\n")
  section_name = ss[0]
  assert ss[1].startswith("// base address:")
  section_address = int(ss[1].split(" ")[-1], 16)
  #print(f"section {section_name} @ 0x{section_address:X}")
  for de in ss[2:]:
    deff, name, addr = de.split()
    assert deff.startswith("#define")
    addr = int(addr, 16)
    regs[name] = addr
    secs[name] = (section_name, section_address)

for k in regs:
  if not k.endswith("BASE_IDX"): continue
  base_idx = regs[k]
  section_name, section_address = secs[k]
  real_name = k.split("_BASE_IDX")[0]
  reg = regs[real_name]
  if base_idx == 1:
    print(f"{real_name:s} reg:0x{0xa000+reg:x}") # 0x{0xa000+reg:x}  # {section_name} @ 0x{section_address//4:X}")

