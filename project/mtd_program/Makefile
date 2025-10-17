BMV2_SWITCH_EXE = simple_switch_grpc

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$*.p4.p4info.txtpb

RUN_SCRIPT = main.py

ifndef TOPO
TOPO = topology.json
endif

P4_PROGRAMS = switch.p4 router.p4
compiled_json := $(patsubst %.p4,$(BUILD_DIR)/%.json,$(P4_PROGRAMS))

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args := $(foreach prog,$(compiled_json),-j $(prog))
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

all: run

cli: build
	sudo PYTHONPATH=../../utils/ python3 $(RUN_SCRIPT) -t $(TOPO) $(run_args)

run: build
	sudo PYTHONPATH=../../utils/ python3 $(RUN_SCRIPT) --test -t $(TOPO) $(run_args)

stop:
	sudo mn -c

build: dirs $(compiled_json)

$(BUILD_DIR)/%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
