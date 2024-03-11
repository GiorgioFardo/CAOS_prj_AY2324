/*
 * FreeRTOS V202212.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/*-----------------------------------------------------------
 * Application specific definitions.
 *
 * These definitions should be adjusted for your particular hardware and
 * application requirements.
 *
 * THESE PARAMETERS ARE DESCRIBED WITHIN THE 'CONFIGURATION' SECTION OF THE
 * FreeRTOS API DOCUMENTATION AVAILABLE ON THE FreeRTOS.org WEB SITE.
 *
 * See http://www.freertos.org/a00110.html
 *----------------------------------------------------------*/

// START DEMO PARAMETERS

#define MEM_SIZE 56                                                   //Total size of a mem block
#define CURRENT_PADDING 8                                             //the freertos current padding between cells
#define TEST_ADD_NUM 10                                               //MIN: 1 MAX: 26, number of allocations
#define DEBUG 0
#define DELAY 2
#define DELAY_ALLOCATION 2
#define DELAY_FREE 2
#define DELAY_START 5

#define NUM_OF_BLOCKS 6                                               //number of blocks
#define AVAL_MEM_SIZE (MEM_SIZE-CURRENT_PADDING)                      //byte per block of memory
#define BYTE_PER_ROW 8                                                //bit in a printed row of a single mem block

#define BASE_ADDRESS 0x20040000UL                                     //base address of the heap
#define BSIZE_HEX (0x1*MEM_SIZE)                                      //BLOCK size (bits) in hex


extern uint8_t memPlusAlignment;                                  //array to use for the demo (to show a visual rappresentation)
extern const size_t xHeapStructSize;                              //size of the heap structure
extern uint8_t alignement;                                        //the required alignement
extern uint8_t separatorBlockArr[NUM_OF_BLOCKS][NUM_OF_BLOCKS];   //array to show a mem block split

// END DEMO PARAMETERS

#define configUSE_TRACE_FACILITY 0
#define configGENERATE_RUN_TIME_STATS 0
#define configSUPPORT_DYNAMIC_ALLOCATION 1
#define configUSE_TICKLESS_IDLE         0
#define configUSE_PREEMPTION			0
#define configUSE_IDLE_HOOK				0
#define configUSE_TICK_HOOK				1
#define configCPU_CLOCK_HZ				( ( unsigned long ) 25000000 )
#define configTICK_RATE_HZ				( ( TickType_t ) 1000 )
#define configMINIMAL_STACK_SIZE		( ( unsigned short ) 80 )
#define configTOTAL_HEAP_SIZE			( ( size_t ) ( 4 * 1024 ) )
#define configMAX_TASK_NAME_LEN			( 12 )
#define configUSE_16_BIT_TICKS			0
#define configIDLE_SHOULD_YIELD			0
#define configUSE_CO_ROUTINES 			0
#define configUSE_MUTEXES				1
#define configUSE_RECURSIVE_MUTEXES		1
#define configCHECK_FOR_STACK_OVERFLOW	2
#define configUSE_MALLOC_FAILED_HOOK	1
#define configUSE_QUEUE_SETS			1
#define configUSE_COUNTING_SEMAPHORES	1

#define configMAX_PRIORITIES			( 9UL )
#define configMAX_CO_ROUTINE_PRIORITIES ( 2 )
#define configQUEUE_REGISTRY_SIZE		10
#define configSUPPORT_STATIC_ALLOCATION	1

/* Timer related defines. */
#define configUSE_TIMERS				1
#define configTIMER_TASK_PRIORITY		( configMAX_PRIORITIES - 4 )
#define configTIMER_QUEUE_LENGTH		20
#define configTIMER_TASK_STACK_DEPTH	( configMINIMAL_STACK_SIZE * 2 )

#define configUSE_TASK_NOTIFICATIONS	1
#define configTASK_NOTIFICATION_ARRAY_ENTRIES 3

/* Set the following definitions to 1 to include the API function, or zero
to exclude the API function. */

#define INCLUDE_vTaskPrioritySet				0
#define INCLUDE_uxTaskPriorityGet				0
#define INCLUDE_vTaskDelete						0
#define INCLUDE_vTaskCleanUpResources			0
#define INCLUDE_vTaskSuspend					0
#define INCLUDE_vTaskDelayUntil					1
#define INCLUDE_vTaskDelay						1
#define INCLUDE_uxTaskGetStackHighWaterMark		0
#define INCLUDE_xTaskGetSchedulerState			0
#define INCLUDE_xTimerGetTimerDaemonTaskHandle	0
#define INCLUDE_xTaskGetIdleTaskHandle			0
#define INCLUDE_xSemaphoreGetMutexHolder		0
#define INCLUDE_eTaskGetState					1
#define INCLUDE_xTimerPendFunctionCall			0
#define INCLUDE_xTaskAbortDelay					0
#define INCLUDE_xTaskGetHandle					0

/* This demo makes use of one or more example stats formatting functions.  These
format the raw data provided by the uxTaskGetSystemState() function in to human
readable ASCII form.  See the notes in the implementation of vTaskList() within
FreeRTOS/Source/tasks.c for limitations. */
#define configUSE_STATS_FORMATTING_FUNCTIONS	0

#define configKERNEL_INTERRUPT_PRIORITY 		( 255 )	/* All eight bits as QEMU doesn't model the priority bits. */
/* !!!! configMAX_SYSCALL_INTERRUPT_PRIORITY must not be set to zero !!!!
See http://www.FreeRTOS.org/RTOS-Cortex-M3-M4.html. */
#define configMAX_SYSCALL_INTERRUPT_PRIORITY 	( 4 )

/* Use the Cortex-M3 optimised task selection rather than the generic C code
version. */
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0

/* The Win32 target is capable of running all the tests tasks at the same
 * time. */
#define configRUN_ADDITIONAL_TESTS				1

/* The test that checks the trigger level on stream buffers requires an
allowable margin of error on slower processors (slower than the Win32
machine on which the test is developed). */
#define configSTREAM_BUFFER_TRIGGER_LEVEL_TEST_MARGIN   4

#ifndef __IASMARM__ /* Prevent C code being included in IAR asm files. */
	void vAssertCalled( const char *pcFileName, uint32_t ulLine );
	#define configASSERT( x ) if( ( x ) == 0 ) vAssertCalled( __FILE__, __LINE__ );
#endif

#define intqHIGHER_PRIORITY		( configMAX_PRIORITIES - 5 )
#define bktPRIMARY_PRIORITY		( configMAX_PRIORITIES - 3 )
#define bktSECONDARY_PRIORITY	( configMAX_PRIORITIES - 4 )

#endif /* FREERTOS_CONFIG_H */