import ida_auto, ida_hexrays, ida_pro, idc
ida_auto.auto_wait()
ok = ida_hexrays.init_hexrays_plugin()
ida_hexrays.decompile_many(idc.ARGV[1], None, ida_hexrays.VDRUN_NEWFILE | ida_hexrays.VDRUN_SILENT | ida_hexrays.VDRUN_MAYSTOP)
ida_pro.qexit(0)
