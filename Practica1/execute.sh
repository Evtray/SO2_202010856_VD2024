#!/bin/bash

# Directorios donde se encuentran los módulos
CAPTURE_MEM_DIR="/home/evtray/Escritorio/project/modules/capture_mem_mod"
TRACK_SYSCALLS_DIR="/home/evtray/Escritorio/project/modules/track_syscall_usage"
IO_THROTTLE_DIR="/home/evtray/Escritorio/project/modules/io_throttle_mod"
SYSTEM_STATS_DIR="/home/evtray/Escritorio/project/modules/sistem_stats"

# Compilar los módulos
echo "Compilando módulos..."
make -C "$CAPTURE_MEM_DIR" clean
make -C "$CAPTURE_MEM_DIR"

make -C "$TRACK_SYSCALLS_DIR" clean
make -C "$TRACK_SYSCALLS_DIR"

make -C "$IO_THROTTLE_DIR" clean
make -C "$IO_THROTTLE_DIR"

make -C "$SYSTEM_STATS_DIR" clean
make -C "$SYSTEM_STATS_DIR"

# Usar el PPID para el io_throttle_mod
PID="$PPID"
echo "Usando PID=$PID para io_throttle_mod"

# Cargar módulos en el kernel
echo "Cargando módulos..."
sudo insmod "$CAPTURE_MEM_DIR/capture_mem_mod.ko"
sudo insmod "$TRACK_SYSCALLS_DIR/track_syscalls_mod.ko"
sudo insmod "$IO_THROTTLE_DIR/io_throttle_mod.ko" pid=$PID
sudo insmod "$SYSTEM_STATS_DIR/system_stats.ko"

# Mostrar la salida de los archivos en /proc
echo "==== /proc/capture_mem ===="
cat /proc/capture_mem
echo

echo "==== /proc/track_syscalls ===="
cat /proc/track_syscalls
echo

echo "==== /proc/io_throttle (PID=$PID) ===="
cat /proc/io_throttle
echo

echo "==== /proc/system_stats ===="
cat /proc/system_stats
echo

echo "Listo. Si deseas descargar los módulos:"
echo "sudo rmmod system_stats"
echo "sudo rmmod io_throttle_mod"
echo "sudo rmmod track_syscalls_mod"
echo "sudo rmmod capture_mem_mod"