{ pkgs ? import <nixpkgs> { } }:

let
  python = pkgs.python312;

  runtimeLibs = with pkgs; [
    stdenv.cc.cc.lib # libstdc++.so.6, libgcc_s
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

    echo "Python $(python --version | cut -d' ' -f2) venv active: $VIRTUAL_ENV"
  '';
}
