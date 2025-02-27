CC = gcc
CFLAGS = -Wall -Wextra -g -I.
LDFLAGS = -lm

# Detect OS for platform-specific settings
UNAME := $(shell uname)

# Optional libraries for different platforms 
# (set to 0 if not available)
USE_CURL = 0  # Set to 1 if libcurl is installed
USE_CJSON = 0 # Set to 1 if cJSON is installed
USE_SECCOMP = 0
USE_SANDBOX = 0

# Library flags based on availability
ifeq ($(USE_CURL), 1)
    CFLAGS += -DUSE_CURL
    LDFLAGS += -lcurl
endif

ifeq ($(USE_CJSON), 1)
    CFLAGS += -DUSE_CJSON
    LDFLAGS += -lcjson
endif

# Platform-specific settings
ifeq ($(UNAME),Linux)
    ifeq ($(USE_SECCOMP), 1)
        CFLAGS += -DUSE_SECCOMP
        LDFLAGS += -lseccomp
    endif
endif

ifeq ($(UNAME),Darwin)
    # macOS-specific flags
    LDFLAGS += -framework Security
    ifeq ($(USE_SANDBOX), 1)
        CFLAGS += -DUSE_SANDBOX
    endif
endif

SRCS = main.c
OBJS = $(SRCS:.c=.o)
HEADERS = static-analysis.h heuristics.h api_shadowing.h pe_parser.h

TARGET = harkonnen

.PHONY: all clean install run gui sandbox-test nn-test deep-scan

all: $(TARGET) gui-check

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f *.o *.dSYM

# Check for Python and Tkinter for GUI
gui-check:
	@echo "Checking for Python and Tkinter..."
	@python3 -c "import tkinter" 2>/dev/null && echo "Tkinter found, GUI available!" || echo "Warning: Tkinter not found, GUI will not be available"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 755 harkonnen_gui.py /usr/local/bin/harkonnen-gui

# Start the GUI
gui:
	@echo "Starting Harkonnen GUI..."
	@if [ -x "$(shell command -v python3)" ]; then \
		python3 -c "import tkinter" 2>/dev/null && python3 harkonnen_gui.py || \
		(echo "Error: Tkinter not found. Please install Python Tkinter package."); \
	else \
		echo "Error: Python 3 not found. Please install Python 3."; \
	fi

run: $(TARGET)
	./$(TARGET) $(ARGS)

# Special target for sandbox testing
sandbox-test: $(TARGET)
	./$(TARGET) -b -m -n $(ARGS)
	
# Neural network only test
nn-test: $(TARGET)
	./$(TARGET) -n $(ARGS)

# Full deep scan with all features
deep-scan: $(TARGET)
	./$(TARGET) -d -b -m -n -k $(ARGS)

# Platform-specific build targets
linux: CC = gcc
linux: CFLAGS += -DLINUX
linux: all

macos: CC = clang
macos: CFLAGS += -DMACOS
macos: all

# Create a .app bundle for macOS
macos-app: macos
	@echo "Creating macOS app bundle..."
	mkdir -p Harkonnen.app/Contents/MacOS
	mkdir -p Harkonnen.app/Contents/Resources
	cp Info.plist Harkonnen.app/Contents/
	cp $(TARGET) Harkonnen.app/Contents/MacOS/
	cp harkonnen_gui.py Harkonnen.app/Contents/MacOS/
	cp run_binsleuth.py Harkonnen.app/Contents/MacOS/
	cp binsleuth.pth Harkonnen.app/Contents/Resources/
	chmod +x Harkonnen.app/Contents/MacOS/harkonnen_gui.py
	@echo "App bundle created at Harkonnen.app"