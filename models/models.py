from mongoengine import *
import datetime
import json

class CpuInfo(EmbeddedDocument):
    ctx_switches = IntField()
    interrupts = IntField()
    soft_interrupts = IntField()
    syscalls = IntField()

class NetworkInfo(EmbeddedDocument):
    byte_sent = IntField()
    byte_received = IntField()
    packets_sent = IntField()
    packets_received = IntField()
    no_of_sent_error = IntField()
    no_of_received_error = IntField()
    sent_packets_droped = IntField()
    received_pakets_droped = IntField()    

class VirtualMemory(EmbeddedDocument):
    total = IntField()
    available = IntField()
    used = IntField()
    free = IntField()
    used_percentage = DecimalField()
    remaining_percentage = DecimalField()

class SwapMemory(EmbeddedDocument):
    total = IntField()    
    used = IntField()
    free = IntField()
    used_percentage = DecimalField()
    remaining_percentage = DecimalField()


class Memory(EmbeddedDocument):
    virtual_memory = EmbeddedDocumentField(VirtualMemory)
    swap_memory = EmbeddedDocumentField(SwapMemory)

class Network(EmbeddedDocument):
    network_info = EmbeddedDocumentField(NetworkInfo)

class Cpu(EmbeddedDocument):
    cpu_info = EmbeddedDocumentField(CpuInfo)    


class GatewayStatus(Document):
    memory = EmbeddedDocumentField(Memory)
    network = EmbeddedDocumentField(Network)
    cpu = EmbeddedDocumentField(Cpu)
    timestamp = StringField()

class Statastic(Document):
    timestamp = StringField()
    boot_time = StringField()
    cpu_utilization = DecimalField()
    mem_utilization = DecimalField()
    uptime = IntField()
    temperature = DecimalField()
    firmware_status = StringField()
    device_id = StringField()

class ProcessInfo(Document):
    pid = IntField()
    cpu = DecimalField()
    memory = DecimalField()
    status = StringField()
    name = StringField()
    nice = IntField()


class InternetLog(Document):
    device_id = StringField()
    from_timestamp = StringField()
    to_timestamp = StringField()
    status = StringField()
    firmware_status = StringField()

