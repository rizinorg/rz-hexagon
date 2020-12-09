RZ_PLUGIN_PATH=$(shell rz -hh|grep USER_PLUGINS|awk '{print $$2}')
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)

CFLAGS?=-g -fPIC

# RzAsm plugin
RZASM_NAME=hexagon_asm
RZASM_CFLAGS=$(CFLAGS) $(shell pkg-config --cflags rz_asm)
RZASM_LDFLAGS=$(CFLAGS) -shared $(shell pkg-config --libs rz_asm)
RZASM_OBJS=asm_hexagon.o hexagon.o hexagon_disas.o
RZASM_SRC=$(pathsubst %.o, %.c, $(RZASM_OBJS))
RZASM_LIB=$(RZASM_NAME).$(SO_EXT)

# RzAnalysis plugin
RZANALYSIS_NAME=hexagon_analysis
RZANALYSIS_CFLAGS=$(CFLAGS) $(shell pkg-config --cflags rz_analysis)
RZANALYSIS_LDFLAGS=$(CFLAGS) -shared $(shell pkg-config --libs rz_analysis)
RZANALYSIS_OBJS=analysis_hexagon.o hexagon.o hexagon_disas.o hexagon_analysis.o
RZANALYSIS_SRC=$(pathsubst %.o, %.c, $(RZANALYSIS_OBJS))
RZANALYSIS_LIB=$(RZANALYSIS_NAME).$(SO_EXT)

all: $(RZASM_LIB) $(RZANALYSIS_LIB)

clean:
	rm -f $(RZASM_LIB) $(RZANALYSIS_LIB) $(RASM_OBJS) $(RZANALYSIS_OBJS)

$(RZASM_LIB): $(RASM_OBJS)
	$(CC) $(RZASM_CFLAGS) $(RASM_LDFLAGS) $(RASM_OBJS) -o $(RASM_LIB)

$(RZANALYSIS_LIB): $(RZANALYSIS_OBJS)
	$(CC) $(RZANALYSIS_CFLAGS) $(RZANALYSIS_LDFLAGS) $(RZANALYSIS_OBJS) -o $(RZANALYSIS_LIB)

%.o: %.c
	$(CC) $(RZASM_CFLAGS) $(RZANALYSIS_CFLAGS) -c $< -o $@

install:
	cp -f $(RZASM_NAME).$(SO_EXT) $(RZ_PLUGIN_PATH)
	cp -f $(RZANALYSIS_NAME).$(SO_EXT) $(RZ_PLUGIN_PATH)

uninstall:
	rm -f $(RZ_PLUGIN_PATH)/$(RZASM_NAME).$(SO_EXT)
	rm -f $(RZ_PLUGIN_PATH)/$(RZANALYSIS_NAME).$(SO_EXT)

