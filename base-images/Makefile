ifndef COMPONENTS
  COMPONENTS=go-base go-builder postgres redis
endif

build: $(COMPONENTS)
$(COMPONENTS):
	make -C $@ build tag

test:
	for c in $(COMPONENTS); do make -C $$c test; done

clean:
	for c in $(COMPONENTS); do make -C $$c clean; done

tag:
	for c in $(COMPONENTS); do make -C $$c tag; done

publish:
	for c in $(COMPONENTS); do make -C $$c publish; done

.PHONY: $(COMPONENTS) build clean test tag publish
.SILENT: