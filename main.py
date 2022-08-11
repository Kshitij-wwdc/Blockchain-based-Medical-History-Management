from random import randint
from hashlib import sha256
import datetime
import json


def main():
    # Ask for username and value of x
    username = input("Enter your username: ")
    secret_x = input("Enter value of your secret, x: ")

    # Separate logic for admin and non-admin
    if not username == "admin":
        # Load the user details and confirm if secret and public keys match
        user = None
        with open('users.json', 'r+') as f:
            users = []
            try:
                users = json.load(f)
            except:
                pass

        for x in users:
            if x['username'] == username:
                user = User.from_dictionary(x)
                break
        if not user:
            print("Invalid user!")
            return

        try:
            secret_x = int(secret_x)
        except:
            print(f"Invalid secret for {username}!")
            return

        #verify secret
        if not user.y == pow(user.g, secret_x, user.p):
            print(f"\nInvalid secret for {username}!")
            return

        while True:
            print("\n****** MENU ******")
            print("1. Create transaction")
            print("2. View your transactions")
            print("Press q to quit")
            option = -1
            while option == -1:
                try:
                    option = input("\nEnter your option: ")
                    if option == 'q':
                        print("Exiting!")
                        return
                    option = int(option)
                except:
                    print("Invalid option\n")
                    option = -1

            if option == 1:
                # Create a transction with ZKP info
                print("*** NEW TRANSACTION ***")
                hospital = ''
                doctorname = ''
                diagnosis = ''

                hospital = input("Enter the Hospital Name: ")
                doctorname = input("Enter Doctor's Name: ")
                diagnosis = input("Enter the diagnosis: ")

                transaction = Transaction()
                transaction.timestamp = datetime.datetime.now()
                transaction.diagnosis = diagnosis
                transaction.doctorname = doctorname
                transaction.hospital = hospital
                transaction.create_transaction(secret_x, user.p, user.g)


                transaction.from_user = username
                # We now add the transaction to the transactions file
                with open('transactions.json', 'r+') as f:
                    transactions = []
                    try:
                        transactions = json.load(f)
                    except:
                        pass
                    f.seek(0)
                    f.truncate()
                    transactions.append(transaction.to_dictionary())
                    json.dump(transactions, f)

                print("Transaction successfully added to pending queue!!\n")
            elif option == 2:
                # Go through all blocks and find cur user's transactions
                print("\n\n*** VIEW USER TRANSACTIONS ***")
                with open('blocks.json', 'r+') as f:
                    blocks = []
                    try:
                        blocks = json.load(f)
                    except:
                        pass
                if not blocks:
                    print("No user transactions exist!")
                blocks = [Block.from_dictionary(x) for x in blocks]
                transactions = [(x, y) for x in blocks for y in x.transactions]

                print(f"Number of verified transactions: {len(transactions)}\n")
                for block, transaction in transactions:
                    print(f"Block hash: {block.hash}")
                    print(f"Block mined at: {str(block.timestamp)}")
                    print(f"Transaction Id: {transaction.id}")
                    print(f"Hospital : {transaction.hospital}")
                    print(f"Doctor's Name: {transaction.doctorname}")
                    print(f"Diagnosis: {str(transaction.diagnosis)}")
                    print(f"Time: {str(transaction.timestamp)}")
                    
                    print("\n")

    else:
        if not secret_x == "password":
            print("Invalid secret for admin account")
            return


        while True:
            print("\n****** MENU ******")
            print("1. View pending transactions")
            print("2. Mine block")
            print("Press q to exit!")

            option = -1
            while option == -1:
                try:
                    option = input("\nEnter your option: ")
                    if option == 'q':
                        print("Exiting!")
                        return
                    option = int(option)
                except:
                    print("Invalid option\n")
                    option = -1

            if option == 1:
                # Load all the transactions and display them
                with open('transactions.json', 'r+') as f:
                    transactions = []
                    try:
                        transactions = json.load(f)
                    except:
                        pass

                print("\n**** PENDING TRANSACTIONS ****")
                print(f"Number of pending transactions: {len(transactions)}\n")
                for tranasction in transactions:
                    transaction = Transaction.from_dictionary(tranasction)
                    print(f"Transaction Id: {transaction.id}")
                    print(f"Hospital : {transaction.hospital}")
                    print(f"Doctor's Name: {transaction.doctorname}")
                    print(f"Diagnosis: {transaction.diagnosis}")
                    print(f"Time: {str(transaction.timestamp)}")
                    print(f"Valid Transaction: {transaction.verify_transaction()}")
                    print("\n")
            elif option == 2:
                # Create block using pending transactions
                with open('transactions.json', 'r+') as f:
                    transactions = []
                    try:
                        transactions = json.load(f)
                    except:
                        pass

                print("\n**** MINING NEW BLOCK ****")
                print(f"Number of pending transactions: {len(transactions)}\n")
                if not transactions:
                    print("No transactions to process")
                    continue

                verified_transactions = []
                # Verify transactions
                for transaction in transactions:
                    transaction = Transaction.from_dictionary(transaction)
                    if not transaction.verify_transaction():
                        print(f'Transaction failed verification')
                    else:
                        print(f'Successfully verified transaction #{transaction.id} ')
                        verified_transactions.append(transaction)

                # Get a list of blocks
                with open('blocks.json', 'r+') as f:
                    blocks = []
                    try:
                        blocks = json.load(f)
                    except:
                        pass

                # find the newest block
                latest_block = None
                for block in blocks:
                    block = Block.from_dictionary(block)
                    if not latest_block:
                        latest_block = block
                        continue
                    if block.timestamp > latest_block:
                        latest_block = block.timestamp

                # Create a block using verified transactions
                parent_hash = latest_block.hash if latest_block else ""
                block = Block()
                block.create_block(parent_hash, verified_transactions)
                block.mine_block()

                # Add block to list
                with open('blocks.json', 'w+') as f:
                    blocks = []
                    try:
                        blocks = json.load(f)
                    except:
                        pass
                    print(blocks)
                    blocks.append(block.to_dictionary())
                    print(blocks)
                    json.dump(blocks, f)

                # Wipe the transactions list
                open('transactions.json', 'w+').close()

                print(f"Created block with hash {block.hash}")

def hexstr_to_bitarray(hexstr, min_length=64):
    ret = bitstr_to_bitarray(bin(int(hexstr, base=16))[2:])
    for i in range(0, min_length - len(ret)):
        ret.insert(0, 0)
    return ret

def bitstr_to_bitarray(bitstr):
    return [1 if i == '1' else 0 for i in bitstr]

def bitarray_to_hexstr(bitarray):
    bitstr = "".join(['1' if i == 1 else '0' for i in bitarray])
    return hex(int(bitstr, base=2))


class User:
    def __init__(self):
        self.name = ""
        self.p = 0
        self.g = 0
        self.y = 0   # generated from p, g, and x

    def gen_pub(self, secret_x):
        self.y = pow(self.g, secret_x, self.p)

    @classmethod
    def from_dictionary(cls, from_dict):
        user = cls()
        for key, val in user.__dict__.items():
            if key in from_dict:
                user.__dict__[key] = from_dict[key]
        return user

    def to_dictionary(self):
        return self.__dict__.copy()


class Block:
    def __init__(self):
        self.hash = ""
        self.parent = ""
        self.transactions = []
        self.timestamp = 0

    def create_block(self, parent_block, transactions):
        self.parent = parent_block
        self.transactions = transactions
        self.timestamp = datetime.datetime.now()

    def mine_block(self):
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # We convert everything to a json string and then sha256 it
        data = self.to_dictionary()
        del data['hash']
        data = json.dumps(data)
        hash = sha256(data.encode('utf-8')).hexdigest()
        # take 16 characters at a time and encrypt them using DES
        final = ""
        for i in range(0, 4):
            final += bitarray_to_hexstr(DES().encrypt(hexstr_to_bitarray(hash[(i * 16):((i+1) * 16)]), DES.K))[2:]
        return final

    @classmethod
    def from_dictionary(cls, from_dict):
        block = cls()
        for key, val in block.__dict__.items():
            if key in from_dict:
                block.__dict__[key] = from_dict[key]
        block.timestamp = datetime.datetime.fromisoformat(block.timestamp)
        block.transactions = [Transaction.from_dictionary(x) for x in block.transactions]
        return block

    def to_dictionary(self):
        ret = self.__dict__.copy()
        ret['transactions'] = [x.to_dictionary() for x in self.transactions]
        ret['timestamp'] = self.timestamp.isoformat()
        return ret


class Transaction:
    def __init__(self):
        self.id = 0
        self.from_user = ''
        self.hospital = ''
        self.doctorname = ''
        self.diagnosis = ''
        self.timestamp = 0

        self.h = 0 # (g ^ 4) mod p
        self.s = [] # (r + bx) mod (p-1), where b = 0, 1

    def create_transaction(self, secret, p, g):
        r = randint(0, p-2)
        self.id = randint(0, 1000000)
        self.h = pow(g, r, p)
        self.s.append(r % (p-1))  # when b = 0
        self.s.append((r + secret) % (p-1))  # when b = 1


    def verify_transaction(self):
        # identify the user and get g, b, p
        user = None
        with open('users.json', 'r') as f:
            users = []
            try:
                users = json.load(f)
            except:
                pass

        for x in users:
            if x['username'] == self.from_user:
                user = User.from_dictionary(x)
                break
        if not user:
            return False

        for b in range(0, 2):
            if not pow(user.g, self.s[b], user.p) == ((self.h * pow(user.y, b)) % user.p):
                return False
        return True

    @classmethod
    def from_dictionary(cls, from_dict):
        transaction = cls()
        for key, val in transaction.__dict__.items():
            if key in from_dict:
                transaction.__dict__[key] = from_dict[key]
        transaction.timestamp = datetime.datetime.fromisoformat(transaction.timestamp)
        return transaction

    def to_dictionary(self):
        ret = self.__dict__.copy()
        ret['timestamp'] = self.timestamp.isoformat()
        return ret


class DES:

    # The master key
    K = hexstr_to_bitarray("133457799BBCDFF1")

    # Initial permutation table for the data
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7]

    # Initial Permutation table for the key
    PC_1 = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    # Permutation table applied on shifted key to get round key
    PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32]

    # Expansion permutation to convert 32-bit blocks to 48 bits
    E = [32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1]

    # Substitution boxes, S1.. S8
    S_BOX = [

    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
    ]

    # Permutation to be applied after substitution
    P = [16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25]

    # Final permutation after all rounds
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25]

    #Matrix that determine the shift for each round of keys
    SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    def initial_permutation(self, data):
        ret = [0 for i in range(0, 64)]
        for i in range(0, 64):
            ret[i] = data[DES.IP[i] - 1]
        return ret

    def round(self, left_half, right_half, round_key):
        feistel_ret = self.feistel(right_half, round_key)
        xor_ret = [left_half[i] ^ feistel_ret[i] for i in range(0, 32)]

        return right_half, xor_ret

    def feistel(self, data, round_key):
        expansion = [data[DES.E[i] - 1] for i in range(0, 48)]
        expansion = [expansion[i] ^ round_key[i] for i in range(0, 48)]
        ret = []
        ret += self.sub_box(expansion[0:6], DES.S_BOX[0])
        ret += self.sub_box(expansion[6:12], DES.S_BOX[1])
        ret += self.sub_box(expansion[12:18], DES.S_BOX[2])
        ret += self.sub_box(expansion[18:24], DES.S_BOX[3])
        ret += self.sub_box(expansion[24:30], DES.S_BOX[4])
        ret += self.sub_box(expansion[30:36], DES.S_BOX[5])
        ret += self.sub_box(expansion[36:42], DES.S_BOX[6])
        ret += self.sub_box(expansion[42:48], DES.S_BOX[7])
        return [ret[DES.P[i] - 1] for i in range(0, 32)]

    def sub_box(self, data, sub_box):
        row = (data[0] << 1) | data[5]
        column = (data[1] << 3) | (data[2] << 2) | (data[3] << 1) | data[4]
        ret = sub_box[row][column]
        return  [1 if x=='1' else 0 for x in "{0:04b}".format(ret)]

    def key_schedule(self, initial_key):
        round_keys = []
        key = [initial_key[DES.PC_1[i] - 1] for i in range(0, 56)]
        half_1, half_2 = key[0:28], key[28:56]
        for i in range(0, 16):
            for x in range(0, self.SHIFT[i]):
                half_1.append(half_1.pop(0))
                half_2.append(half_2.pop(0))

            total = half_1 + half_2

            round_key = [0 for i in range(0, 48)]
            for i in range(0, 48):
                round_key[i] = total[DES.PC_2[i] - 1]

            # round_key = [total[DES.PC_2[i]] for i in range(0, 48)]
            round_keys.append(round_key)
        return round_keys

    def final_permutation(self, data):
        ret = [0 for i in range(0, 64)]
        for i in range(0, 64):
            ret[i] = data[DES.FP[i] - 1]
        return ret

    def encrypt(self, data, key, decrypt=False):
        """Data -> a binary list of 64 bits"""
        round_keys = self.key_schedule(key)
        if decrypt:
            round_keys = round_keys[-1:]

        data = self.initial_permutation(data)
        left_half, right_half = data[0:32], data[32:64]
        for i in range(0, 16):
            left_half, right_half = self.round(left_half, right_half, round_keys[i])
        left_half, right_half = right_half, left_half
        data = left_half + right_half  # Undo the switch introduced by the last round
        return self.final_permutation(data)

    def decrypt(self, data, key):
        self.encrypt(data, key, True)

if __name__ == '__main__':
    main()