deps: clean
deps: export onlyDeps = true
deps: run

.PHONY: run
run:
	mkdir -p ./deps && \
	mkdir -p ./build/pcap_demo && cd ./build/pcap_demo && \
	cmake ../.. && \
	make
	
.PHONY: clean
clean:
	rm -rf ./build ./deps

build: clean
build: export MODE = debug
build: run

release: clean
release: export MODE = release
release: run
