

run:
	mkdir -p ./build && cd ./build && \
	cmake .. && \
	make
clean:
	rm -rf ./build
.PHONY: run

build: clean
build: export MODE = debug
build: run

release: clean
release: export MODE = release
release: run
