from check1 import check_1_1
from check2 import check_2_1, check_2_2, check_2_3
from check3 import check_3_1, check_3_2, check_3_3, check_3_4, check_3_5
from check4 import check_4_1, check_4_2, check_4_3, check_4_4, check_4_5
from check5 import check_5_1, check_5_2, check_5_3, check_5_4
from check6 import check_6_1, check_6_2, check_6_3
from check7 import check_7_1, check_7_2

CONFIG_FILE = "/etc/mongod.conf"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except:
        return {}

def print_result(section, status, reason, recommendation):
    print(f"[{'OK' if status else 'FAIL'}] {section}")
    print(f"    Reason        : {reason}")
    print(f"    Recommendation: {recommendation}\n")


if __name__ == "__main__":
    config = load_config()
    check_1_1()
    check_2_1(config)
    check_2_2()
    check_2_3(config)
    check_3_1()
    check_3_2(config)
    check_3_3()
    check_3_4()
    check_3_5()
    check_4_1(config)
    check_4_2(config)
    check_4_3(config)
    check_4_4(config)
    check_4_5()
    check_5_1(config)
    check_5_2(config)
    check_5_3(config)
    check_5_4(config)
    check_6_1(config)
    check_6_2()
    check_6_3()
    check_7_1(config)
    check_7_2(config)
