## Ghidra Switch Loader

A loader for Ghidra intended to support a variety of Nintendo Switch file formats. Improvements are still being made, and I intend to match the functionality of the IDA loader as best as possible.

## Building

- Ensure you have JAVA_HOME set to the path of your JDK 11 installation.
- Set GHIDRA_INSTALL_DIR to your Ghidra install directory. This can be done by adding it to your path, running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``, or by using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew`` (as described below)
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation
- Extract the zip file to ``ghidra_9.0/Ghidra/Extensions``. It is very important that this path is correct, ``ghidra_9.0/Extensions`` *will not* work.