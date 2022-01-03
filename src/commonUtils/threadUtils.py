# ******************************************************
# Copyright © 2020-2021 VMware, Inc. All rights reserved.
# ******************************************************

"""
Description: Module which handles multi-threading operations
"""
import logging
import queue
from queue import Empty
import threading
import traceback
from concurrent.futures import wait
logger = logging.getLogger('mainLogger')


class Thread:
    """
        Description: Class that performs all threads related functions
    """

    def __init__(self, maxNumberOfThreads=75):
        """
            Description: Initialization of Thread class
            Parameters:  - Max number of threads to spawn at a given time (INT)
        """
        # initializing queue and lock for threads
        self.threadQueue = queue.Queue()
        self.numOfThread = maxNumberOfThreads
        # rlock used instead of lock such that lock can be released by the thread which has acquired it not by other threads as in case of lock
        self.lock = threading.RLock()
        # this flag is used to decide whether to stop main-thread or not
        self.stopValue = False
        # counter for naming the threads
        self.threadCounter = 0
        # dictionary to store the return values from a function executed by a thread
        self.returnValues = {}

    def _createQueue(self, daemon=False, **kwargs):
        """
            Description: This method creates the queue for the specified tasks.
            Parameters: daemon  - Value to decide whether to run thread in background or not(BOOLEAN)
        """
        threadCount = min(self.numOfThread, self.threadQueue.qsize())
        for _ in range(threadCount):
            # incrementing the thread counter
            self.threadCounter += 1
            worker = threading.Thread(target=self._runThread, kwargs=kwargs)
            worker.name = f'Thread-{self.threadCounter}'
            worker.setDaemon(daemon)
            worker.start()

    def _runThread(self, **kwargs):
        """
            Description: This method executes the threads.
            Returns: True
        """
        try:
            while not self.threadQueue.empty():
                function, saveOutputKey, block, threadName, arguments = self.threadQueue.get(timeout=10, block=False)
                # If thread name is provided, set name of thread to that name
                if threadName:
                    threading.current_thread().name = threadName
                _args, _kwargs = arguments
                try:
                    output = function(*_args, **_kwargs)
                    # saving return value from function
                    if saveOutputKey:
                        self.returnValues[saveOutputKey] = output
                    else:
                        self.returnValues[function.__name__] = output
                except Empty:
                    continue
                except Exception as err:
                    if kwargs.get('logException'):
                        logging.exception(err)
                    else:
                        logger.error(f"Error: {str(err)}")
                        logger.debug(traceback.format_exc())
                    # set the value of stop flag to true in case of any exception
                    self.stopValue = True
                    # Acknowledge the task done
                    self.threadQueue.task_done()
                    # if block param is provided then empty the queue in case of failure
                    if block:
                        # Acquiring the lock to clear the queue
                        self.acquireLock()
                        while not self.threadQueue.empty():
                            self.threadQueue.get(block=False)
                            self.threadQueue.task_done()
                        # Releasing the lock after queue is empty
                        self.releaseLock()
                        return
                else:
                    self.threadQueue.task_done()
            return True
        except:
            raise

    def spawnThread(self, func, *args, saveOutputKey=None, block=False, threadName=None, **kwargs):
        """
            Description: This method puts the task in the queue for further execution by threads.
            Parameters: func          - The object of the target function for the thread (OBJECT)
                        args          - Arguments used in target function
                        saveOutputKey - Key to be used to store return value from function (STRING)
                        block         - Key used to block further thread execution if a thread encounters any error (BOOLEAN)
                        threadName    - Name used to define a threadName, if not provided then default will be used (STRING)
                        kwargs        - Keyword arguments to be used in target function
        """
        self.threadQueue.put((func, saveOutputKey, block, threadName, (args, kwargs)), timeout=10)

    def joinThreads(self, **kwargs):
        """
            Description: This method blocks the main thread till all the tasks in the queue are complete.
        """
        self.returnValues = {}
        # Resetting the value of stop flag for new queue
        self.stopValue = False
        # Resetting the value of thread counter for new queue
        self.threadCounter = 0
        # Creating a queue for the number of specified threads so that only specified number of threads are spawned at a time
        self._createQueue(**kwargs)
        # Wait for all the threads to execute then return to main thread
        self.threadQueue.join()
        logger.debug('All threads executed successfully')

    def stop(self):
        """
            Description: This method returns the value of stop flag
            Returns: value to stop flag
        """
        return self.stopValue

    def acquireLock(self):
        """
            Description: This method is used to acquire lock by thread for a blocking call.
        """
        self.lock.acquire(blocking=True)
        logger.debug("Lock acquired by thread - '{}'".format(threading.currentThread().getName()))

    def releaseLock(self):
        """
            Description: This method is used to release thread lock.
        """
        self.lock.release()
        logger.debug("Lock released by thread - '{}'".format(threading.currentThread().getName()))


def waitForThreadToComplete(futures):
    """
    Description : This method waits for the threads of threadPoolExecutor to complete and stop on KeyboardInterrupt
    Parameters: futures - list of references of the spawned threads (LIST)
    """
    if not isinstance(futures, list):
        raise Exception("Futures parameter is supposed to be a list")
    # Fetching the references of threads that have completed and that have not
    done, notDone = wait(futures, timeout=0)
    POLL_INTERVAL = 2
    try:
        # Keep looping until all the threads complete execution
        while notDone:
            # This loop continues will all threads/futures have completed execution
            freshlyDone, notDone = wait(notDone, timeout=POLL_INTERVAL)
            done |= freshlyDone
        # getting exception if generated by any of the threads
        threadFailed = False
        for thread in done:
            try:
                thread.result()
            except:
                import traceback
                logger.debug(traceback.format_exc())
                threadFailed = True
        if threadFailed:
            raise Exception("VCD V2T Migration Tool Failed, Please Check the logs for the exceptions") from None
    # When CTRL+C is hit, need to stop all the threads/futures
    except KeyboardInterrupt:
        # Iterating over futures/threads that have not completed execution to cancel them
        for future in notDone:
            _ = future.cancel()
        _ = wait(notDone, timeout=None)