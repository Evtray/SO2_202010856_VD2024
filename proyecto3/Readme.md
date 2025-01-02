## Laboratorio Sistemas Operativos 2 ##

### PROYECTO 3 ###

### **Nombre:** Edwin Sandoval Lopez
### **Carne:** 202010856  

**Introducción y Objetivos del Proyecto:**
- **Objetivo General**: Evitar que procesos acaparen toda la memoria disponible en el sistema, permitiendo mayor equidad en la asignación de recursos.
- **Objetivos Específicos**:
  - Comprender las llamadas internas de asignación de memoria en el kernel (como `mmap`).
  - Desarrollar las operaciones CRUD de control de límites de memoria sobre los procesos en el kernel.
  - Practicar la compilación y modificación de un kernel de Linux.

## Implementación de nuevas llamadas al sistema:

- Se desarrollaron cuatro syscalls con las firmas:
  - `long so2_add_memory_limit(pid_t process_pid, size_t memory_limit)`
  - `long so2_get_memory_limits(struct memory_limitation __user *u_buf, size_t max_entries, int __user *processes_returned)`
  - `long so2_update_memory_limit(pid_t process_pid, size_t memory_limit)`
  - `long so2_remove_memory_limit(pid_t process_pid)`
- Solo **usuarios sudoers** (por ejemplo `UID=0`) pueden actualizar o remover límites (en este ejemplo).
- Se maneja una **lista enlazada** en el **espacio del kernel** para registrar los procesos limitados.

## 1. Estructura del Proyecto
- `include/linux/so2_memory_limiter.h`: Contiene la definición del `struct memory_limitation` y prototipos de funciones internas.  
- `kernel/so2_memory_limiter.c`: Implementa la lógica de lista enlazada y las funciones internas.  
- `kernel/so2_syscalls.c`: Contiene la definición de cada syscall (`SYSCALL_DEFINE`) e invoca las funciones de `so2_memory_limiter.c`.  

## 2. Pruebas
- Se incluyen scripts en C que llaman a las syscalls:
  1. Verificando manejo de errores (por ejemplo, pasar un PID inexistente).
  2. Confirmando el correcto registro de nuevos procesos en la lista.
  3. Probando la obtención de la lista de procesos limitados con distintos tamaños de buffer.
  4. Actualizando un límite y revisando si se reportan los errores esperados.
  5. Removiendo un proceso de la lista y validando su correcta eliminación.

## 3. Conclusión Personal
En el desarrollo de esta fase, aprendimos cómo **integrar** nuevas syscalls en el kernel de Linux, la **complejidad** de mantener una estructura de datos coherente bajo condiciones de concurrencia (uso de spinlocks), y la importancia de manejar los **códigos de error** de forma consistente entre el espacio de usuario y el espacio de kernel.  
La parte más **difícil** fue la configuración del entorno de desarrollo y asegurarnos de que las llamadas a funciones internas del kernel cumplieran con las restricciones de licencias y del estilo de codificación.  
Este proyecto nos permitió profundizar en la gestión de memoria a bajo nivel y en cómo un proceso realmente solicita memoria al kernel mediante llamadas como `malloc` y `mmap`. Sin duda, **ha sido un gran aprendizaje** de las entrañas del SO.  
