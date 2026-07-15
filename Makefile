# Сборка статического бинаря под Windows 7 SP1 и выше.
#
# Требования, из которых вытекают флаги:
#   - на целевых машинах ничего не устанавливается, поэтому -static:
#     ни libgcc, ни libstdc++, ни редистрибутива рядом не будет;
#   - тулчейн обязан быть MSVCRT-сборкой MinGW-w64, а не UCRT:
#     ucrtbase.dll появилась только в Windows 10, на стоковой Win7 её нет;
#   - _WIN32_WINNT=0x0601 задаёт нижний порог - Windows 7.

CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra \
            -D_WIN32_WINNT=0x0601 -DWINVER=0x0601
LDFLAGS  := -static -static-libgcc -static-libstdc++
LDLIBS   := -lcrypt32 -ladvapi32 -lwinscard

SRCDIR   := src
BUILDDIR := build
TARGET   := $(BUILDDIR)/cert-migrator.exe

SRCS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

# Показывает, от каких DLL зависит бинарь. Ожидаем только системные:
# kernel32, advapi32, crypt32, msvcrt. Появление ucrtbase или libgcc/libstdc++
# означает, что на Windows 7 бинарь не запустится.
check: $(TARGET)
	objdump -p $(TARGET) | grep "DLL Name"

clean:
	rm -rf $(BUILDDIR)
