## Laboratorio Sistemas Operativos 2 ##

### PRACTICA 2 ###

### **Nombre:** Edwin Sandoval Lopez
### **Carne:** 202010856  

### **Cronograma de Actividades**

**Cronograma en 7 Días**

| **Día** | **Actividad Principal**                                              | **Entregable/Objetivo**                                              |
|:-------:|:--------------------------------------------------------------------:|:---------------------------------------------------------------------:|
| **1**   | **Análisis y Diseño**                                               | - Confirmar requerimientos y números de syscall.<br>- Decidir estructura de archivos.<br>- Preparar entorno de compilación. |
| **2**   | **Implementar Syscall 551**                                         | - Crear/actualizar cabecera `tamalloc_syscalls.h`.<br>- Implementar `tamalloc_get_stats` (MAP_NORESERVE).<br>- Agregar entrada 551 en `syscall_64.tbl`. |
| **3**   | **Implementar Syscall 552**                                         | - Desarrollar `tamalloc_get_global_stats` (iterar todos los procesos).<br>- Sumar VmSize y VmRSS en MB.<br>- Agregar entrada 552 en `syscall_64.tbl`. |
| **4**   | **Implementar Syscall 553**                                         | - Crear `tamalloc_get_indiviual_stats` (estadísticas por PID).<br>- Calcular VmSize, VmRSS, % de uso y OOM Score.<br>- Agregar entrada 553 en `syscall_64.tbl`. |
| **5**   | **Pruebas Unitarias (User Space)**                                   | - Desarrollar/ajustar programas de prueba en C.<br>- Compilar kernel y correr pruebas iniciales.<br>- Validar respuestas (direcciones, estadísticas). |
| **6**   | **Pruebas Avanzadas y Documentación**                                | - Evaluar rendimiento, probar múltiples PIDs y tamaños de memoria.<br>- Redactar documentación (instrucciones, flujos internos, etc.). |
| **7**   | **Correcciones Finales y Entrega**                                  | - Solucionar errores restantes.<br>- Realizar compilación final del kernel y pruebas definitivas.<br>- Entregar todo (código, documentación, binarios de test). |