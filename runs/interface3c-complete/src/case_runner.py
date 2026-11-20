"""Keep one source-level case failure from killing the verifier process."""
import multiprocessing


def _worker(callback, cell, channel):
    try:
        channel.send({"status": "observed", "row": callback(cell)})
    except Exception as error:
        channel.send({
            "status": "case_exec_failure",
            "reason": type(error).__name__ + ": " + str(error),
        })
    finally:
        channel.close()


def run_case(callback, cell, timeout=10):
    context = multiprocessing.get_context("fork")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(callback, cell, writer))
    process.start()
    writer.close()
    process.join(timeout)
    if process.is_alive():
        process.kill()
        process.join()
        result = {"status": "case_exec_failure", "reason": "case_timeout"}
    elif process.exitcode != 0:
        result = {
            "status": "case_exec_failure",
            "reason": "case_process_exit_" + str(process.exitcode),
        }
    elif not reader.poll():
        result = {"status": "case_exec_failure", "reason": "missing_case_result"}
    else:
        result = reader.recv()
    reader.close()
    return result
