from . import *

checker = SmartmeterChecker()
checker.place_flag()
checker.check_service(1)
checker.check_flag(1)

checker._tick = 3
checker.place_flag()
checker.check_service(1)
checker.check_flag(1)
checker.check_service(3)
checker.check_flag(3)
