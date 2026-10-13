#
# Copyright 2013-2021 Software Radio Systems Limited
#
# This file is part of srsRAN
#
# srsRAN is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# srsRAN is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# A copy of the GNU Affero General Public License can be found in
# the LICENSE file in the top-level directory of this distribution
# and at http://www.gnu.org/licenses/.
#

file(GLOB_RECURSE SOURCES "*.c")

if (RPATH)
  set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
endif (RPATH)

add_executable(cellinspector ${SOURCES})

# srsran_mac must come before srsran_common (console symbol resolution)
set(SRSRAN_SOURCES srsran_phy srsran_radio srsran_mac srsran_common srslog support system)

target_link_libraries(cellinspector
                              -Wl,--start-group
                              ${SRSRAN_SOURCES}
                              -Wl,--end-group
                              ${CMAKE_THREAD_LIBS_INIT}
                              ${LIBCONFIG_LIBRARY}
                              ${ATOMIC_LIBS}
                              config)

if (LIBASN4G)
    target_link_libraries(cellinspector ${LIBASN4G_LIBRARY})
endif(LIBASN4G)

if (RPATH)
  set_target_properties(cellinspector PROPERTIES INSTALL_RPATH ".")
endif (RPATH)
