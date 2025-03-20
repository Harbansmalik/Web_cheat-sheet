# Race Conditions
A race condition occurs when multiple processes or threads access shared resources concurrently, leading to unpredictable outcomes and potential data corruption due to timing dependencies in execution order.

## Mitigations of race conditions:

### ✅ 1. Implement Transaction Locking
Use database-level locks to ensure that only one process modifies a record at a time.
Example (MySQL - SELECT … FOR UPDATE):
```text
BEGIN;
SELECT balance FROM accounts WHERE user_id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 100 WHERE user_id = 1;
COMMIT;
```
🔹 This locks the row until the transaction completes, preventing simultaneous modifications.
### ✅ 2. Use Atomic Operations
Atomic operations ensure that a process completes fully or not at all, preventing partial execution.
Example (Incrementing a value safely in SQL):
```text
UPDATE accounts SET balance = balance - 100 WHERE user_id = 1;
```
🔹 This prevents race conditions when multiple users try modifying the balance at the same time.
 ### ✅ 3. Implement Optimistic Concurrency Control (OCC)
Store a version number or timestamp for each record.
When updating, check if the record has been modified before committing the changes.
Example (Using a version column):
```text
UPDATE orders 
SET status = 'shipped', version = version + 1 
WHERE id = 123 AND version = 5;
```
🔹 If another process modified version = 5 before, the update will fail and retry.
### ✅ 4. Use Queues for Critical Operations
Queueing mechanisms (e.g., RabbitMQ, Kafka, Redis) ensure that operations are processed sequentially.
Example: Instead of processing two withdrawal requests simultaneously, enqueue them and process them one by one.

### ✅ 5. Implement Mutex (Mutual Exclusion) Locks
Use mutex locks in multi-threaded environments to prevent concurrent access.
Example (Using Python threading.Lock()):
```text
import threading

lock = threading.Lock()

def withdraw(amount):
    with lock:
        balance = get_balance()
        if balance >= amount:
            update_balance(balance - amount)
```
🔹 This ensures that only one process can execute the critical section at a time.
### ✅ 6. Enforce Rate-Limiting & Retry Mechanisms
Use rate limits to prevent multiple rapid requests that could trigger a race condition.
Example (Nginx Rate Limiting):
```text
limit_req_zone $binary_remote_addr zone=limit_zone:10m rate=5r/s;
```
🔹 This ensures users can only send a limited number of requests per second.
### ✅ 7. Use Idempotent Operations
Idempotent operations ensure that repeated execution produces the same result.
Example: Instead of:
```text
POST /transfer?amount=100
```
Use:
```text
PUT /transfer?transaction_id=123&amount=100
```
🔹 This ensures the same transaction isn’t executed multiple times.
