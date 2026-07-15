# Сборка статического 32-битного бинаря под Windows 7 SP1 и выше.
#
# Требования, из которых вытекают флаги:
#   - на целевых машинах ничего не устанавливается, поэтому -static:
#     ни libgcc, ни libstdc++, ни редистрибутива рядом не будет;
#   - тулчейн обязан быть MSVCRT-сборкой MinGW-w64, а не UCRT:
#     ucrtbase.dll появилась только в Windows 10, на стоковой Win7 её нет;
#   - _WIN32_WINNT=0x0601 задаёт нижний порог - Windows 7;
#   - i686 (32-бит): 32-битный бинарь запускается и на x86, и на x64 Win7+,
#     и только он может напрямую грузить 32-битный COM rtComLite.
#
# CXX переопределяется под конкретный путь к тулчейну, напр.:
#   make CXX=/путь/к/i686tc/mingw32/bin/g++

# Windows-only проект: фиксируем cmd как шелл make, иначе рецепты ведут себя
# по-разному в зависимости от того, есть ли на PATH sh.exe (Git Bash).
ifeq ($(OS),Windows_NT)
  SHELL := cmd.exe
  .SHELLFLAGS := /c
endif

CXX      ?= i686-w64-mingw32-g++
# -MMD -MP: генерировать .d-файлы зависимостей от заголовков, чтобы правка
# .h вызывала пересборку зависящих .o (иначе ловятся рассинхроны сигнатур).
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -MMD -MP \
            -D_WIN32_WINNT=0x0601 -DWINVER=0x0601
LDFLAGS  := -static -static-libgcc -static-libstdc++
LDLIBS   := -lcrypt32 -ladvapi32 -lwinscard -lole32 -loleaut32 -luuid -lurlmon

SRCDIR   := src
BUILDDIR := build
TARGET   := $(BUILDDIR)/cert-migrator.exe

SRCS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(patsubst $(SRCDIR)/%.cpp,$(BUILDDIR)/%.o,$(SRCS))

# Иконка exe: собираем ресурс только если файл иконки существует, иначе
# сборка идёт без иконки и не ломается.
WINDRES ?= $(dir $(CXX))windres
ICO := $(wildcard assets/app.ico)
ifneq ($(ICO),)
  RES := $(BUILDDIR)/app.res.o
endif

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(OBJS) $(RES)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(RES) $(LDLIBS)

$(BUILDDIR)/app.res.o: $(SRCDIR)/app.rc $(ICO) | $(BUILDDIR)
	$(WINDRES) --include-dir . $< -O coff -o $@

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Подхватываем сгенерированные зависимости от заголовков.
-include $(OBJS:.o=.d)

$(BUILDDIR):
	if not exist "$(BUILDDIR)" mkdir "$(BUILDDIR)"

# Показывает, от каких DLL зависит бинарь. Ожидаем только системные:
# kernel32, advapi32, crypt32, msvcrt, winscard. Появление ucrtbase или
# libgcc/libstdc++ означает, что на Windows 7 бинарь не запустится.
check: $(TARGET)
	objdump -p $(TARGET) | findstr "DLL"

clean:
	if exist "$(BUILDDIR)" rmdir /s /q "$(BUILDDIR)"
