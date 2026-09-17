{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "rop3-eval-env";

  buildInputs = with pkgs; [
    (python3.withPackages (ps: with ps; [
      capstone
      pefile
      pyelftools
      pyyaml
      macholib
      pandas
      seaborn
      matplotlib
      pyqt6
      joblib
      requests
      libarchive-c
    ]))
    wimlib
  ];
}
