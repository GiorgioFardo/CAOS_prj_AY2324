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


/******************************************************************************
 * See https://www.freertos.org/freertos-on-qemu-mps2-an385-model.html for
 * instructions.
 *
 * This project provides a demo application regarding task scheduling.
 * First, compile and execute this demo with the pre-emptive scheduler, by ensuring that in
 * FreeRTOSConfig.h the configUSE_PREEMPTION variable is set 1.
 * Then, change the configUSE_PREEMPTION variable to 0, in order to run the demo with a non pre-emptive scheduler.
 * This file implements the code that is demo specific, including also the
 * hardware setup and FreeRTOS hook functions.
 *
 * Running in QEMU:
 * Use the following commands to start the application running in a way that
 * enables the debugger to connect, omit the "-s -S" to run the project without
 * the debugger:
 * qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -kernel [path-to]/RTOSDemo.out -nographic -serial stdio -semihosting -semihosting-config enable=on,target=native -s -S
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include "queue.h"

/* Standard includes. */
#include <stdio.h>
#include <string.h>


/* printf() output uses the UART.  These constants define the addresses of the
required UART registers. */
#define UART0_ADDRESS 	( 0x40004000UL )
#define UART0_DATA		( * ( ( ( volatile uint32_t * )( UART0_ADDRESS + 0UL ) ) ) )
#define UART0_STATE		( * ( ( ( volatile uint32_t * )( UART0_ADDRESS + 4UL ) ) ) )
#define UART0_CTRL		( * ( ( ( volatile uint32_t * )( UART0_ADDRESS + 8UL ) ) ) )
#define UART0_BAUDDIV	( * ( ( ( volatile uint32_t * )( UART0_ADDRESS + 16UL ) ) ) )
#define TX_BUFFER_MASK	( 1UL )

/*
 * Printf() output is sent to the serial port.  Initialise the serial hardware.
 */
static void prvUARTInit( void );

#define main_SIMPLE_DEMO 1
/* The period of each task. The times are converted from
milliseconds to ticks using the pdMS_TO_TICKS() macro. */
#define mainTASK_FREQUENCY1_MS			pdMS_TO_TICKS( 20000UL )
#define mainTASK_FREQUENCY2_MS			pdMS_TO_TICKS( 30000UL ) 
#define mainTIMER_FREQUENCY_MS			pdMS_TO_TICKS( 1200000UL ) 

/*-----------------------------------------------------------*/
static char const * const pcTextForTask1 = "Task 1 is running\n";
static char const * const pcTextForTask2 = "Task 2 is running\n";
static char const * const pcTextForTask3 = "Task 3 is running\n";
static char const * const pcTextForTask4 = "Task 4 is running\n";
static char const * const pcTextForTask5 = "Task 5 is running\n";

/*
 * The callback function executed when the software timer expires.
 */
static void prvSendTimerCallback( TimerHandle_t xTimerHandle );

static void vTask1( void *pvParameters );
static void vTask2( void *pvParameters );

/* A software timer that is started from the tick hook. */
static TimerHandle_t xTimer = NULL;

/*-----------------------------------------------------------*/



void main( void )
{
	/* See https://www.freertos.org/freertos-on-qemu-mps2-an385-model.html for
	instructions. */

	/* Hardware initialisation.  printf() output uses the UART for IO. */
	prvUARTInit();

    const TickType_t xTimerPeriod = mainTIMER_FREQUENCY_MS;

		/* Start the tasks as described in the comments at the top of this
		file. */
		xTaskCreate(vTask1,			/* The function that implements the task. */
					"Task 1", 							/* The text name assigned to the task - for debug only as it is not used by the kernel. */
					configMINIMAL_STACK_SIZE, 		/* The size of the stack to allocate to the task. */
					(void *)pcTextForTask1, 		/* The parameter passed to the task, works in a stack fashion */
					1,                              /* The priority assigned to the task. */
					NULL);							/* The task handle is not required, so NULL is passed. */

		xTaskCreate(vTask1, "Task 2", configMINIMAL_STACK_SIZE, (void *)pcTextForTask2, 2, NULL );
        
        xTaskCreate(vTask1, "Task 3", configMINIMAL_STACK_SIZE, (void *)pcTextForTask3, 3, NULL );

        xTaskCreate(vTask2, "Task 4", configMINIMAL_STACK_SIZE, (void *)pcTextForTask4, 2, NULL );

        xTaskCreate(vTask2, "Task 5", configMINIMAL_STACK_SIZE, (void *)pcTextForTask5, 1, NULL );
		/* Create the software timer, but don't start it yet. */
		xTimer = xTimerCreate( "Timer",				/* The text name assigned to the software timer - for debug only as it is not used by the kernel. */
								xTimerPeriod,		/* The period of the software timer in ticks. */
								pdTRUE,				/* xAutoReload is set to pdTRUE, so this is an auto-reload timer. */
								NULL,				/* The timer's ID is not used. */
				 				prvSendTimerCallback);/* The function executed when the timer expires. */
		xTimerStart( xTimer, 0 ); /* The scheduler has not started so use a block time of 0. */

		/* Start the tasks and timer running. */
		vTaskStartScheduler();
	/* If all is well, the scheduler will now be running, and the following
	line will never be reached.  If the following line does execute, then
	there was insufficient FreeRTOS heap memory available for the idle and/or
	timer tasks	to be created.  See the memory management section on the
	FreeRTOS web site for more details.  NOTE: This demo uses static allocation
	for the idle and timer tasks so this line should never execute. */
	for( ;; );

}
/*-----------------------------------------------------------*/
static void vTask1( void *pvParameters )
{
TickType_t xNextWakeTime;
const TickType_t xBlockTime = mainTASK_FREQUENCY1_MS;
const char *pcTaskName;
pcTaskName = (char *)pvParameters;
	/* Initialise xNextWakeTime - this only needs to be done once. */
	xNextWakeTime = xTaskGetTickCount();

	for( ;; )
	{
        printf("%s\n",pcTaskName);
		/* Place this task in the blocked state until it is time to run again.
		The block time is specified in ticks, pdMS_TO_TICKS() was used to
		convert a time specified in milliseconds into a time specified in ticks.
		While in the Blocked state this task will not consume any CPU time. */
		vTaskDelayUntil( &xNextWakeTime, xBlockTime );
	}
}
/*-----------------------------------------------------------*/
static void vTask2( void *pvParameters )
{
TickType_t xNextWakeTime;
const TickType_t xBlockTime = mainTASK_FREQUENCY2_MS;
const char *pcTaskName;
pcTaskName = (char *)pvParameters;

	/* Initialise xNextWakeTime - this only needs to be done once. */
	xNextWakeTime = xTaskGetTickCount();

	for( ;; )
	{
        printf("%s\n",pcTaskName);
		/* Place this task in the blocked state until it is time to run again.
		The block time is specified in ticks, pdMS_TO_TICKS() was used to
		convert a time specified in milliseconds into a time specified in ticks.
		While in the Blocked state this task will not consume any CPU time. */
		vTaskDelayUntil( &xNextWakeTime, xBlockTime );
	}
}
/*-----------------------------------------------------------*/
static void prvSendTimerCallback( TimerHandle_t xTimerHandle )
{
	/* This is the software timer callback function.  The software timer has a
	period of two seconds and is reset each time a key is pressed.  This
	callback function will execute if the timer expires, which will only happen
	if a key is not pressed for two seconds. */

	/* Avoid compiler warnings resulting from the unused parameter. */
	( void ) xTimerHandle;
    printf("Timer reset.\n");
}
/*-----------------------------------------------------------*/

void vApplicationMallocFailedHook( void )
{
	/* vApplicationMallocFailedHook() will only be called if
	configUSE_MALLOC_FAILED_HOOK is set to 1 in FreeRTOSConfig.h.  It is a hook
	function that will get called if a call to pvPortMalloc() fails.
	pvPortMalloc() is called internally by the kernel whenever a task, queue,
	timer or semaphore is created using the dynamic allocation (as opposed to
	static allocation) option.  It is also called by various parts of the
	demo application.  If heap_1.c, heap_2.c or heap_4.c is being used, then the
	size of the	heap available to pvPortMalloc() is defined by
	configTOTAL_HEAP_SIZE in FreeRTOSConfig.h, and the xPortGetFreeHeapSize()
	API function can be used to query the size of free heap space that remains
	(although it does not provide information on how the remaining heap might be
	fragmented).  See http://www.freertos.org/a00111.html for more
	information. */
	printf( "\r\n\r\nMalloc failed\r\n" );
	portDISABLE_INTERRUPTS();
	for( ;; );
}
/*-----------------------------------------------------------*/

void vApplicationIdleHook( void )
{
	/* vApplicationIdleHook() will only be called if configUSE_IDLE_HOOK is set
	to 1 in FreeRTOSConfig.h.  It will be called on each iteration of the idle
	task.  It is essential that code added to this hook function never attempts
	to block in any way (for example, call xQueueReceive() with a block time
	specified, or call vTaskDelay()).  If application tasks make use of the
	vTaskDelete() API function to delete themselves then it is also important
	that vApplicationIdleHook() is permitted to return to its calling function,
	because it is the responsibility of the idle task to clean up memory
	allocated by the kernel to any task that has since deleted itself. */
}
/*-----------------------------------------------------------*/

void vApplicationStackOverflowHook( TaskHandle_t pxTask, char *pcTaskName )
{
	( void ) pcTaskName;
	( void ) pxTask;

	/* Run time stack overflow checking is performed if
	configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2.  This hook
	function is called if a stack overflow is detected. */
	printf( "\r\n\r\nStack overflow in %s\r\n", pcTaskName );
	portDISABLE_INTERRUPTS();
	for( ;; );
}
/*-----------------------------------------------------------*/
void vApplicationTickHook( void )
{
    /* This function will be called by each tick interrupt if
    * configUSE_TICK_HOOK is set to 1 in FreeRTOSConfig.h.  User code can be
    * added here, but the tick hook is called from an interrupt context, so
    * code must not attempt to block, and only the interrupt safe FreeRTOS API
    * functions can be used (those that end in FromISR()). */

    #if ( main_SIMPLE_DEMO != 1 )
    {
        extern void vFullDemoTickHookFunction( void );

        vFullDemoTickHookFunction();
    }
    #endif /* main_SIMPLE_DEMO */
}
/*-----------------------------------------------------------*/

void vApplicationDaemonTaskStartupHook( void )
{
	/* This function will be called once only, when the daemon task starts to
	execute (sometimes called the timer task).  This is useful if the
	application includes initialisation code that would benefit from executing
	after the scheduler has been started. */
}
/*-----------------------------------------------------------*/

void vAssertCalled( const char *pcFileName, uint32_t ulLine )
{
volatile uint32_t ulSetToNonZeroInDebuggerToContinue = 0;

	/* Called if an assertion passed to configASSERT() fails.  See
	http://www.freertos.org/a00110.html#configASSERT for more information. */

	printf( "ASSERT! Line %d, file %s\r\n", ( int ) ulLine, pcFileName );

 	taskENTER_CRITICAL();
	{
		/* You can step out of this function to debug the assertion by using
		the debugger to set ulSetToNonZeroInDebuggerToContinue to a non-zero
		value. */
		while( ulSetToNonZeroInDebuggerToContinue == 0 )
		{
			__asm volatile( "NOP" );
			__asm volatile( "NOP" );
		}
	}
	taskEXIT_CRITICAL();
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
used by the Idle task. */
void vApplicationGetIdleTaskMemory( StaticTask_t **ppxIdleTaskTCBBuffer, StackType_t **ppxIdleTaskStackBuffer, uint32_t *pulIdleTaskStackSize )
{
/* If the buffers to be provided to the Idle task are declared inside this
function then they must be declared static - otherwise they will be allocated on
the stack and so not exists after this function exits. */
static StaticTask_t xIdleTaskTCB;
static StackType_t uxIdleTaskStack[ configMINIMAL_STACK_SIZE ];

	/* Pass out a pointer to the StaticTask_t structure in which the Idle task's
	state will be stored. */
	*ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

	/* Pass out the array that will be used as the Idle task's stack. */
	*ppxIdleTaskStackBuffer = uxIdleTaskStack;

	/* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
	Note that, as the array is necessarily of type StackType_t,
	configMINIMAL_STACK_SIZE is specified in words, not bytes. */
	*pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION and configUSE_TIMERS are both set to 1, so the
application must provide an implementation of vApplicationGetTimerTaskMemory()
to provide the memory that is used by the Timer service task. */
void vApplicationGetTimerTaskMemory( StaticTask_t **ppxTimerTaskTCBBuffer, StackType_t **ppxTimerTaskStackBuffer, uint32_t *pulTimerTaskStackSize )
{
/* If the buffers to be provided to the Timer task are declared inside this
function then they must be declared static - otherwise they will be allocated on
the stack and so not exists after this function exits. */
static StaticTask_t xTimerTaskTCB;
static StackType_t uxTimerTaskStack[ configTIMER_TASK_STACK_DEPTH ];

	/* Pass out a pointer to the StaticTask_t structure in which the Timer
	task's state will be stored. */
	*ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

	/* Pass out the array that will be used as the Timer task's stack. */
	*ppxTimerTaskStackBuffer = uxTimerTaskStack;

	/* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
	Note that, as the array is necessarily of type StackType_t,
	configMINIMAL_STACK_SIZE is specified in words, not bytes. */
	*pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}
/*-----------------------------------------------------------*/

static void prvUARTInit( void )
{
	UART0_BAUDDIV = 16;
	UART0_CTRL = 1;
}
/*-----------------------------------------------------------*/

int __write( int iFile, char *pcString, int iStringLength )
{
	int iNextChar;

	/* Avoid compiler warnings about unused parameters. */
	( void ) iFile;

	/* Output the formatted string to the UART. */
	for( iNextChar = 0; iNextChar < iStringLength; iNextChar++ )
	{
		while( ( UART0_STATE & TX_BUFFER_MASK ) != 0 );
		UART0_DATA = *pcString;
		pcString++;
	}

	return iStringLength;
}
/*-----------------------------------------------------------*/

void *malloc( size_t size )
{
	( void ) size;

	/* This project uses heap_4 so doesn't set up a heap for use by the C
	library - but something is calling the C library malloc().  See
	https://freertos.org/a00111.html for more information. */
	printf( "\r\n\r\nUnexpected call to malloc() - should be usine pvPortMalloc()\r\n" );
	portDISABLE_INTERRUPTS();
	for( ;; );

}
