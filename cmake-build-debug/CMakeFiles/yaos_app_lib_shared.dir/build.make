# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /tmp/yaos

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /tmp/yaos/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/yaos_app_lib_shared.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/yaos_app_lib_shared.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/yaos_app_lib_shared.dir/flags.make

CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.o: CMakeFiles/yaos_app_lib_shared.dir/flags.make
CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.o: ../src-shared/circuit.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/tmp/yaos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.o -c /tmp/yaos/src-shared/circuit.cxx

CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /tmp/yaos/src-shared/circuit.cxx > CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.i

CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /tmp/yaos/src-shared/circuit.cxx -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.s

CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.o: CMakeFiles/yaos_app_lib_shared.dir/flags.make
CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.o: ../src-shared/messages.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/tmp/yaos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.o -c /tmp/yaos/src-shared/messages.cxx

CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /tmp/yaos/src-shared/messages.cxx > CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.i

CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /tmp/yaos/src-shared/messages.cxx -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.s

CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.o: CMakeFiles/yaos_app_lib_shared.dir/flags.make
CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.o: ../src-shared/logger.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/tmp/yaos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.o -c /tmp/yaos/src-shared/logger.cxx

CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /tmp/yaos/src-shared/logger.cxx > CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.i

CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /tmp/yaos/src-shared/logger.cxx -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.s

CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.o: CMakeFiles/yaos_app_lib_shared.dir/flags.make
CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.o: ../src-shared/util.cxx
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/tmp/yaos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.o -c /tmp/yaos/src-shared/util.cxx

CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /tmp/yaos/src-shared/util.cxx > CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.i

CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /tmp/yaos/src-shared/util.cxx -o CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.s

# Object files for target yaos_app_lib_shared
yaos_app_lib_shared_OBJECTS = \
"CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.o" \
"CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.o" \
"CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.o" \
"CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.o"

# External object files for target yaos_app_lib_shared
yaos_app_lib_shared_EXTERNAL_OBJECTS =

libyaos_app_lib_shared.a: CMakeFiles/yaos_app_lib_shared.dir/src-shared/circuit.cxx.o
libyaos_app_lib_shared.a: CMakeFiles/yaos_app_lib_shared.dir/src-shared/messages.cxx.o
libyaos_app_lib_shared.a: CMakeFiles/yaos_app_lib_shared.dir/src-shared/logger.cxx.o
libyaos_app_lib_shared.a: CMakeFiles/yaos_app_lib_shared.dir/src-shared/util.cxx.o
libyaos_app_lib_shared.a: CMakeFiles/yaos_app_lib_shared.dir/build.make
libyaos_app_lib_shared.a: CMakeFiles/yaos_app_lib_shared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/tmp/yaos/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX static library libyaos_app_lib_shared.a"
	$(CMAKE_COMMAND) -P CMakeFiles/yaos_app_lib_shared.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/yaos_app_lib_shared.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/yaos_app_lib_shared.dir/build: libyaos_app_lib_shared.a

.PHONY : CMakeFiles/yaos_app_lib_shared.dir/build

CMakeFiles/yaos_app_lib_shared.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/yaos_app_lib_shared.dir/cmake_clean.cmake
.PHONY : CMakeFiles/yaos_app_lib_shared.dir/clean

CMakeFiles/yaos_app_lib_shared.dir/depend:
	cd /tmp/yaos/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /tmp/yaos /tmp/yaos /tmp/yaos/cmake-build-debug /tmp/yaos/cmake-build-debug /tmp/yaos/cmake-build-debug/CMakeFiles/yaos_app_lib_shared.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/yaos_app_lib_shared.dir/depend

