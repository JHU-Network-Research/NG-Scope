# Shared environment setup, sourced by the launchers in this directory.
#
# This exists because the three launchers each need the same UHD images and
# library wiring, and when uhd-find-launch drifted out of sync with the others
# the symptom was a bare "no images directory located" and a USRP that would
# not enumerate.

# Make libsrsran_rf.so and its dlopen'ed RF plugins resolvable.
#
# ngscope is built with RPATH=OFF, and libsrsran_rf.so loads its backends with
# dlopen("libsrsran_rf_uhd.so", RTLD_NOW) -- a bare soname, no path (see
# lib/src/phy/rf/rf_imp.c:430 and rf_dev.h:28-72). Both the top-level RF
# library and its plugins install side by side into $SNAP/usr/lib.
uhd_setup_libs() {
    LD_LIBRARY_PATH="$SNAP/usr/lib:$LD_LIBRARY_PATH"
    for _d in "$SNAP"/usr/lib/*-linux-gnu; do
        [ -d "$_d" ] && LD_LIBRARY_PATH="$_d:$LD_LIBRARY_PATH"
    done
    export LD_LIBRARY_PATH
}

# Point UHD at a directory of FPGA/firmware images.
#
# uhd::get_images_dir() resolves UHD_IMAGES_DIR to a *single* directory and
# only accepts one that exists -- it does not search a ':'-separated list. So
# pick one rather than passing both.
#
# Default to the read-only bundled set ($SNAP/usr/share/uhd/images, the b2xx
# images baked in at build time), which always exists and needs no copying.
# Only prefer the writable per-user directory once it actually has something
# in it, which happens when the user adds x3xx/x4xx images.
uhd_setup_images_dir() {
    _bundled="$SNAP/usr/share/uhd/images"
    _user_dir="$SNAP_USER_COMMON/uhd-images"

    if [ -d "$_user_dir" ] && [ -n "$(ls -A "$_user_dir" 2>/dev/null)" ]; then
        UHD_IMAGES_DIR="$_user_dir"
    else
        UHD_IMAGES_DIR="$_bundled"
    fi
    export UHD_IMAGES_DIR
}

# Seed the writable directory from the bundle, so that once the user starts
# adding images it stays a superset and the b2xx set is never lost.
uhd_seed_user_images_dir() {
    _bundled="$SNAP/usr/share/uhd/images"
    _user_dir="$SNAP_USER_COMMON/uhd-images"

    mkdir -p "$_user_dir"
    if [ -d "$_bundled" ]; then
        cp -rn "$_bundled/." "$_user_dir/" 2>/dev/null || true
    fi
    UHD_IMAGES_DIR="$_user_dir"
    export UHD_IMAGES_DIR
}
