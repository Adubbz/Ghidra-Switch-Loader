## Ghidra Switch Loader

A loader for Ghidra supporting a variety of Nintendo Switch file formats.

## Building
- Ensure you have JAVA_HOME set to the path of your JDK 11 installation.
- Set GHIDRA_INSTALL_DIR to your Ghidra install directory. This can be done by:
    - Adding it to your path
    - Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``.
    - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``.
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (File -> Install Extensions...).