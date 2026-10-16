{ pkgs ? import <nixpkgs> { } }:

let
  python = pkgs.python312;

  runtimeLibs = with pkgs; [
    stdenv.cc.cc.lib # libstdc++.so.6, libgcc_s
    capstone         # libcapstone.so: ropium's C build links & loads it
    zlib
    glib
    libGL
    libxkbcommon
    fontconfig
    freetype
    openssl
    libffi
    bzip2
    xz
    sqlite
    expat
    ncurses
    readline
  ];
in
pkgs.mkShell {
  name = "python-pip-env";

  packages = [
    python
  ]
  ++ (with pkgs; [
    gcc
    gnumake
    cmake
    pkg-config
    git
  ])
  ++ runtimeLibs;

  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath runtimeLibs;

  shellHook = ''
    # Nix sets this to 1980-01-01, which breaks building wheels (zip timestamps)
    unset SOURCE_DATE_EPOCH

    export PIP_DISABLE_PIP_VERSION_CHECK=1
    export PYTHONNOUSERSITE=1

    VENV_DIR="''${VENV_DIR:-.venv}"
    if [ ! -d "$VENV_DIR" ]; then
      echo "Creating virtualenv in $VENV_DIR ..."
      ${python}/bin/python -m venv "$VENV_DIR"
      "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
    fi
    source "$VENV_DIR/bin/activate"

    # Auto-install requirements if present
    if [ -f requirements.txt ]; then
      pip install -q -r requirements.txt
    fi

    # ropium has no working pip package: build it locally into gitignored .ropium/
    # and put its compiled extension on PYTHONPATH so `import ropium` works.
    # if [ -f utils/build_ropium.sh ]; then
    #   bash utils/build_ropium.sh || \
    #     echo "[WARN] ropium build failed; ropium comparison rows will be 'error'"
    # fi
    # export PYTHONPATH="$PWD/.ropium/bin''${PYTHONPATH:+:$PYTHONPATH}"

    # rop4 (a Go port of rop3) has no pip package either, but it ships prebuilt
    # release binaries, so instead of building it we download the pinned release
    # (c-shared library + Python wrapper) into gitignored .rop4/ and put the
    # wrapper on PYTHONPATH so the comparison worker can `import rop4`. The release
    # .so bundles capstone, so there is no libcapstone/Go dependency. The fetch is
    # idempotent (skips when already present) and non-fatal — on failure,
    # compare-tools.py reports rop4 rows as 'error'. Comment this out to fetch rop4
    # by hand instead (bash utils/fetch_rop4.sh), or set ROP4_REF to pin a tag.
    if [ -f utils/fetch_rop4.sh ]; then
      bash utils/fetch_rop4.sh || \
        echo "[WARN] rop4 fetch failed; rop4 comparison rows will be 'error'"
    fi
    export PYTHONPATH="$PWD/.rop4/python''${PYTHONPATH:+:$PYTHONPATH}"

    echo "Python $(python --version | cut -d' ' -f2) venv active: $VIRTUAL_ENV"
  '';
}
