"""Dynamic scheduling for running Luminar based on the selected time interval."""

import asyncio
import logging

from webapp.tasks.luminar import luminar

LOGGING_LEVEL = logging.DEBUG
LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

logging.basicConfig(
    level=LOGGING_LEVEL,
    format=LOGGING_FORMAT,
    handlers=[logging.FileHandler("scim_app.log"), logging.StreamHandler()],
)


# @app.post("/trigger-luminar/")
# async def trigger_luminar():
#     """
#     Asynchronously trigger the luminar task and return success response immediately.
#     """
#     # Run luminar asynchronously in the background.
#     asyncio.create_task(luminar())
#
#     # Return success response immediately
#     return {
#         "status": "success",
#         "message": "Luminar task triggered successfully. This does not wait for the task to complete.",
#     }


# def schedule_luminar(interval):
#     """
#     Schedules the execution of the `luminar` function at a predefined time interval.
#
#     This function uses the `schedule` library to set up a recurring job for the `luminar` function
#     based on the given interval.
#
#     Parameters:
#         interval (str): The time interval for scheduling the `luminar` function.
#                         Supported values:
#                         - "Every 5 min": Schedules every 5 minutes.
#                         - "Every 10 min": Schedules every 10 minutes.
#                         - "Every 60 min": Schedules every hour.
#                         - "Every 6 hours": Schedules every 6 hours.
#                         - "Every 12 hours": Schedules every 12 hours.
#                         - "Every 24 hours": Schedules every 24 hours.
#
#     Returns:
#         None: If a valid interval is passed, the function sets up the schedule for `luminar`.
#               If the interval is invalid, it returns after printing an error message.
#
#     Example:
#         schedule_luminar("Every 5 min")
#         # This schedules the `luminar` function to run every 5 minutes.
#     """
#     if interval == "Every 5 min":
#         schedule.every(5).minutes.do(luminar)
#     elif interval == "Every 10 min":
#         schedule.every(10).minutes.do(luminar)
#     elif interval == "Every 60 min":
#         schedule.every().hour.do(luminar)
#     elif interval == "Every 6 hours":
#         schedule.every(6).hours.do(luminar)
#     elif interval == "Every 12 hours":
#         schedule.every(12).hours.do(luminar)
#     elif interval == "Every 24 hours":
#         schedule.every().day.do(luminar)
#     else:
#         print("Invalid time interval.")
#         return  # pylint: disable=useless-return
#
#
# selected_time_interval = os.environ.get("TIME_INTERVAL", "Every 24 hours")
# schedule_luminar(selected_time_interval)

if __name__ == "__main__":
    # # generate_and_set_secret_key()
    # while True:
    #     schedule.run_pending()
    #     time.sleep(10)
    luminar()
