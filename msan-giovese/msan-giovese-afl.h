/* Environment variable used to pass MSAN SHM ID to the called program. */

#define MSAN_SHM_ENV_VAR "__MSAN_AFL_SHM_ID"

//msan area to communicate possible errors
extern unsigned char *msan_area_ptr;