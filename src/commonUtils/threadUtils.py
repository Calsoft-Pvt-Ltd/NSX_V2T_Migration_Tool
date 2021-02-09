# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which handles multi-threading operations
"""
import logging
import queue
from queue import Empty
import threading

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

    def _createQueue(self, daemon=False):
        """
            Description: This method creates the queue for the specified tasks.
            Parameters: daemon  - Value to decide whether to run thread in background or not(BOOLEAN)

        """
        threadCount = min(self.numOfThread, self.threadQueue.qsize())
        for _ in range(threadCount):
            # incrementing the thread counter
            self.threadCounter += 1
            worker = threading.Thread(target=self._runThread)
            worker.name = f'Thread-{self.threadCounter}'
            worker.setDaemon(daemon)
            worker.start()

    def _runThread(self):
        """
            Description: This method executes the threads.
            Returns: True
        """
        logger.debug("Current number of tasks in queue - {}".format(self.threadQueue.qsize()))
        while not self.threadQueue.empty():
            function, saveOutputKey, block, arguments = self.threadQueue.get(timeout=10, block=False)
            args, kwargs = arguments
            logging.debug("Logs of thread - {}".format(threading.currentThread().getName()))
            try:
                output = function(*args, **kwargs)
                # saving return value from function
                if saveOutputKey:
                    self.returnValues[saveOutputKey] = output
                else:
                    self.returnValues[function.__name__] = output
            except Empty:
                continue
            except Exception as err:
                logging.exception(err)
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

    def spawnThread(self, func, *args, saveOutputKey=None, block=False, **kwargs):
        """
            Description: This method puts the task in the queue for further execution by threads.
            Parameters: func          - The object of the target function for the thread(object)
                        args          - Arguments used in target function
                        saveOutputKey - Key to be used to store return value from function
                        block         - Key used to block further thread execution if a thread ecounters any error
                        kwargs        - Keyword arguements to be used in target function
        """
        self.threadQueue.put((func, saveOutputKey, block, (args, kwargs)), timeout=10)

    def joinThreads(self):
        """
            Description: This method blocks the main thread till all the tasks in the queue are complete.
        """
        self.returnValues = {}
        # Resetting the value of stop flag for new queue
        self.stopValue = False
        # Resetting the value of thread counter for new queue
        self.threadCounter = 0
        # Creating a queue for the number of specified threads so that only specified number of threads are spawned at a time
        self._createQueue()
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
