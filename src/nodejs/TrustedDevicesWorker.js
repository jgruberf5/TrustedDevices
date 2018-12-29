/* jshint esversion: 6 */
/* jshint node: true */
"use strict";

const fs = require("fs");
const certUrl = 'http://localhost:8100/mgmt/shared/device-certificates';
const deviceGroupsUrl = 'http://localhost:8100/mgmt/shared/resolver/device-groups';
const deviceInfoUrl = 'http://localhost:8100/mgmt/shared/identified-devices/config/device-info';
const localauth = 'Basic ' + new Buffer('admin:').toString('base64');
const ACTIVE = 'ACTIVE';
const UNDISCOVERED = 'UNDISCOVERED';
const DEVICEGROUP_PREFIX = 'TrustProxy_';
const MAX_DEVICES_PER_GROUP = 30;

/**
 * Trusted Device Controller
 * @constructor
 */
class TrustedDevicesWorker {

    constructor() {
        this.WORKER_URI_PATH = "shared/TrustedDevices";
        this.isPublic = true;
    }

    /**
     * handle onGet HTTP request to get trusted devices
     * @param {Object} restOperation
     */
    onGet(restOperation) {
        try {
            this.getDevices(false)
                .then((devices) => {
                    restOperation.statusCode = 200;
                    restOperation.body = {
                        devices: devices
                    };
                    this.completeRestOperation(restOperation);
                })
                .catch((err) => {
                    throw err;
                });
        } catch (err) {
            this.logger.severe("GET request to retrieve trusted devices failed: \n%s", err);
            err.httpStatusCode = 400;
            restOperation.fail(err);
        }
    }

    /**
     * handle onPost HTTP request
     * @param {Object} restOperation - body is the declared devices to trust
     */
    onPost(restOperation) {
        try {
            // get the post body from the request
            const declaration = restOperation.getBody();
            if (!declaration || !declaration.hasOwnProperty('devices')) {
                // there was no declaration body submitted, return an error
                const err = new Error();
                err.message = 'declaration missing';
                err.httpStatusCode = 400;
                this.logger.severe("POST request to trusted devices failed: declaration missing");
                restOperation.fail(err);
                return;
            }
            let desiredDevices = declaration.devices;

            if (desiredDevices.length > 0) {
                // Create comparison collections.
                const desiredDeviceDict = {};
                const existingDeviceDict = {};
                // Populate desired comparison collection with targetHost:targetPort as the key.
                desiredDevices.map((device) => {
                    if (!device.hasOwnProperty('targetPort')) {
                        device.targetPort = 443;
                    }
                    desiredDeviceDict[device.targetHost + ":" + device.targetPort] = device;
                });
                try {
                    this.getDevices(true)
                        .then((existingDevices) => {
                            // Populate existing comparison collection with targetHost:targetPort as the key.
                            existingDevices.map((device) => {
                                existingDeviceDict[device.targetHost + ":" + device.targetPort] = device;
                            });
                            for (let device in desiredDeviceDict) {
                                if (device in existingDeviceDict) {
                                    if (existingDeviceDict[device].state === ACTIVE) {
                                        // Device is desired, exists already, and is active. Don't remove it.
                                        existingDevices = existingDevices.filter(t => t.targetHost + ':' + t.targetPort !== device); // jshint ignore:line
                                        // Device is desired, exists alerady, and is active. Don't add it.
                                        desiredDevices = desiredDevices.filter(t => t.targetHost + ':' + t.targetPort !== device); // jshint ignore:line
                                    } else {
                                        // Device is desired, exists already, but trust is not active. Reset it.
                                        this.logger.info('resetting ' + device.targetHost + ':' + device.targetPort + ' because its state is:' + device.state);
                                        if (!desiredDeviceDict[device].hasOwnProperty('targetUsername') ||
                                            !desiredDeviceDict[device].hasOwnProperty('targetPassphrase')) {
                                            const err = new Error();
                                            err.message = 'declared device missing targetUsername or targetPassphrase';
                                            err.httpStatusCode = 400;
                                            restOperation.fail(err);
                                            return;
                                        }
                                    }
                                } else {
                                    // Assure that the device declaration has the needed attributed to add.
                                    if (!desiredDeviceDict[device].hasOwnProperty('targetUsername') ||
                                        !desiredDeviceDict[device].hasOwnProperty('targetPassphrase')) {
                                        const err = new Error();
                                        err.message = 'declared device missing targetUsername or targetPassphrase';
                                        err.httpStatusCode = 400;
                                        restOperation.fail(err);
                                        return;
                                    }
                                }
                            }

                            // Serially remove devices not desired in the declaration.
                            Promise.all([this.removeDevices(existingDevices)])
                                .then(() => {
                                    Promise.all([this.addDevices(desiredDevices)])
                                        .then(() => {
                                            // Get the list of currently trusted devices as
                                            // the response to our declaration.
                                            this.getDevices(false)
                                                .then((devices) => {
                                                    restOperation.statusCode = 200;
                                                    restOperation.body = {
                                                        devices: devices
                                                    };
                                                    this.completeRestOperation(restOperation);
                                                })
                                                .catch((err) => {
                                                    this.logger.severe('Error returning list of devices:' + err.message);
                                                    throw err;
                                                });
                                        });
                                })
                                .catch((err) => {
                                    throw err;
                                });
                        });
                } catch (err) {
                    this.logger.severe("POST request to trusted devices failed:" + err.message);
                    restOperation.fail(err);
                }
            } else {
                // There are no desired deviecs. Remove all existing trusted devices.
                this.removeAllDevices()
                    .then(() => {
                        // Get the list of currently trusted devices as
                        // the response to our declaration.
                        this.getDevices(false)
                            .then((devices) => {
                                restOperation.statusCode = 200;
                                restOperation.body = {
                                    devices: devices
                                };
                                this.completeRestOperation(restOperation);
                            })
                            .catch((err) => {
                                this.logger.severe('Error returning list of devices:' + err.message);
                                throw err;
                            });
                    })
                    .catch((err) => {
                        this.logger.severe('Error removing all trusted devices:' + err.message);
                        throw err;
                    });
            }
        } catch (err) {
            this.logger.severe("POST request to update trusted devices failed: \n%s", err);
            err.httpStatusCode = 400;
            restOperation.fail(err);
        }
    }

    /**
     * Request to resolve device group to add new devices
     * @returns Promise when request completes
     */
    resolveDeviceGroup() {
        return new Promise((resolve, reject) => {
            // get existing device groups
            const deviceGroupsGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(deviceGroupsUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true);
            this.restRequestSender.sendGet(deviceGroupsGetRequest)
                .then((response) => {
                    let respBody = response.getBody();
                    if (!respBody.hasOwnProperty('items')) {
                        this.createDeviceGroup(DEVICEGROUP_PREFIX + 0)
                            .then((response) => {
                                this.logger.info('resolving proxy device group for new device:' + response.groupName);
                                resolve(response.groupName);
                            })
                            .catch((err) => {
                                reject(err);
                            });
                    } else {
                        let deviceGroups = respBody.items;
                        let candidateGroups = [];
                        deviceGroups.map((deviceGroup) => {
                            if (deviceGroup.groupName.startsWith(DEVICEGROUP_PREFIX)) {
                                candidateGroups.push(deviceGroup.groupName);
                            }
                        });
                        if (candidateGroups.length === 0) {
                            this.createDeviceGroup(DEVICEGROUP_PREFIX + '0')
                                .then((response) => {
                                    this.logger.info('resolving proxy device group for new device:' + response.groupName);
                                    resolve(response.groupName);
                                })
                                .catch((err) => {
                                    reject(err);
                                });
                        } else {
                            candidateGroups = candidateGroups.sort();
                            let deviceCountPromises = [];
                            let deviceGroupsCounts = {};
                            candidateGroups.map((cg) => {
                                const devicesGetRequest = this.restOperationFactory.createRestOperationInstance()
                                    .setUri(this.url.parse(deviceGroupsUrl + '/' + cg + '/devices'))
                                    .setBasicAuthorization(localauth)
                                    .setIsSetBasicAuthHeader(true);
                                const devicesPromise = this.restRequestSender.sendGet(devicesGetRequest)
                                    .then((response) => {
                                        deviceGroupsCounts[cg] = response.getBody().items.length;
                                    })
                                    .catch((err) => {
                                        reject(err);
                                    });
                                deviceCountPromises.push(devicesPromise);
                                Promise.all(deviceCountPromises)
                                    .then(() => {
                                        let highestIndex = 0;
                                        let electedDeviceGroup = null;
                                        Object.keys(deviceGroupsCounts).map((cg) => {
                                            if (deviceGroupsCounts[cg] < MAX_DEVICES_PER_GROUP) {
                                                this.logger.info('resolving proxy device group for new device:' + cg);
                                                resolve(cg);
                                            } else {
                                                let index = parseInt(cg.replace(DEVICEGROUP_PREFIX, ''));
                                                if (index > highestIndex) {
                                                    highestIndex = index;
                                                    electedDeviceGroup = DEVICEGROUP_PREFIX + highestIndex;
                                                }
                                            }
                                        });
                                        if (electedDeviceGroup) {
                                            this.createDeviceGroup(electedDeviceGroup)
                                                .then((response) => {
                                                    this.logger.info('resolving proxy device group for new device:' + response.groupName);
                                                    resolve(response.groupName);
                                                })
                                                .catch((err) => {
                                                    reject(err);
                                                });
                                        }
                                    });
                            });
                        }
                    }
                });
        });
    }


    /**
     * Request to create a named device group on the proxy device
     * @returns Promise when request completes
     */
    createDeviceGroup(groupName) {
        return new Promise((resolve, reject) => {
            this.logger.info('creating proxy device group ' + groupName);
            // get existing device groups to find index
            const createBody = {
                "groupName": groupName,
                "display": "Trusted Proxy Device Group",
                "description": "Group to establish trust for control plane request proxying"
            };
            const deviceGroupsPostRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(deviceGroupsUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true)
                .setBody(createBody);
            this.restRequestSender.sendPost(deviceGroupsPostRequest)
                .then((response) => {
                    resolve(response.getBody());
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    /**
     * Request to get all device groups defined on the proxy device
     * @returns Promise when request completes
     */
    getDeviceGroups() {
        return new Promise((resolve, reject) => {
            const deviceGroupsGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(deviceGroupsUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true);
            this.restRequestSender.sendGet(deviceGroupsGetRequest)
                .then((response) => {
                    let respBody = response.getBody();
                    if (!respBody.hasOwnProperty('items')) {
                        // we need to create a device group for our desired devices
                        Promise.all([this.resolveDeviceGroup()])
                            .then((deviceGroupName) => {
                                resolve(deviceGroupName);
                            })
                            .catch(err => {
                                this.logger.severe('could not create device group');
                                reject(err);
                            });
                    }
                    const returnDeviceGroups = [];
                    respBody.items.map((deviceGroup) => {
                        if (deviceGroup.groupName.startsWith(DEVICEGROUP_PREFIX)) {
                            returnDeviceGroups.push(deviceGroup);
                        }
                    });
                    if (!returnDeviceGroups) {
                        this.createDeviceGroup(DEVICEGROUP_PREFIX + '0')
                            .then((response) => {
                                resolve([response.groupName]);
                            })
                            .catch((err) => {
                                reject(err);
                            });
                    } else {
                        resolve(returnDeviceGroups);
                    }
                })
                .catch(err => {
                    this.logger.severe('could not get a list of device groups:' + err.message);
                    reject(err);
                });
        });
    }

    /**
     * Assures devices are in the well know device group on the proxy device
     * @param List of device objects to add to the device group
     * @returns Promise when assurance completes
     */
    addDevices(devicesToAdd) {
        return new Promise((resolve, reject) => {
            if (devicesToAdd.length > 0) {
                const addPromises = [];
                devicesToAdd.map((device) => {
                    const resolvePromise = this.resolveDeviceGroup()
                        .then((deviceGroupName) => {
                            const devicesUrl = deviceGroupsUrl + '/' + deviceGroupName + '/devices';
                            // build a request to get device groups
                            const createBody = {
                                "userName": device.targetUsername,
                                "password": device.targetPassphrase,
                                "address": device.targetHost,
                                "httpsPort": device.targetPort
                            };
                            const devicePostRequest = this.restOperationFactory.createRestOperationInstance()
                                .setUri(this.url.parse(devicesUrl))
                                .setBasicAuthorization(localauth)
                                .setIsSetBasicAuthHeader(true)
                                .setBody(createBody);
                            const deviceAddPromise = this.restRequestSender.sendPost(devicePostRequest)
                                .then((response) => {
                                    this.logger.info('added ' + device.targetHost + ':' + device.targetPort + ' to proxy device group ' + deviceGroupName);
                                })
                                .catch((err) => {
                                    reject(err);
                                });
                            addPromises.push(deviceAddPromise);
                        })
                        .catch((err) => {
                            reject(err);
                        });
                    addPromises.push(resolvePromise);
                });
                Promise.all(addPromises)
                    .then(() => {
                        wait(500).then(() => {
                            resolve();
                        });
                    })
                    .catch(err => {
                        reject(err);
                    });

            } else {
                resolve();
            }
        });
    }

    /**
     * Assures devices are no longer trusted or trust the proxy device
     * @param List of device objects to remove trust
     * @returns Promise when assurance completes
     */
    removeDevices(devicesToRemove) {
        return new Promise((resolve, reject) => {
            if (devicesToRemove.length > 0) {
                const deletePromises = [];
                this.getProxyMachineId()
                    .then((machineId) => {
                        devicesToRemove.map((device) => {
                            if (device.isBigIP) {
                                // While the trust is still established, remove the proxy certificate
                                // from the trusted device. Then after, remove the device from the proxy device.
                                this.removeCertificateFromTrustedDevice(device, machineId)
                                    .then(() => {
                                        // Remove the trusted device certificate if it registered properly.
                                        if (device.hasOwnProperty('machineId')) {
                                            deletePromises.push(this.removeCertificateFromProxy(device.machineId));
                                        }
                                    })
                                    .catch((err) => {
                                        this.logger.severe('could not remove proxy certificate from trusted device.');
                                        reject(err);
                                    });
                            }
                            // Remove the trusted device from the device group.
                            deletePromises.push(this.removeDevice(device));
                        });
                        Promise.all(deletePromises)
                            .then(() => {
                                resolve();
                            })
                            .catch((err) => {
                                this.logger.severe('could not remove trusted device from the proxy');
                                reject(err);
                            });
                    });
            } else {
                resolve();
            }
        });
    }

    /**
     * Assures no devices are trusted or trust the proxy device
     * @returns Promise when assurance completes
     */
    removeAllDevices() {
        return new Promise((resolve, reject) => {
            this.getDevices(true)
                .then((devices) => {
                    if (devices.length > 0) {
                        const deletePromises = [];
                        this.getProxyMachineId()
                            .then((machineId) => {
                                devices.map((device) => {
                                    if (device.isBigIP) {
                                        // While the trust is still established, remove the proxy certificate
                                        // from the trusted device. Then after, remove the device from the proxy.
                                        this.removeCertificateFromTrustedDevice(device, machineId)
                                            .then(() => {
                                                // Remove the trusted device certificate if it registered properly.
                                                if (device.hasOwnProperty('machineId')) {
                                                    deletePromises.push(this.removeCertificateFromProxy(device.machineId));
                                                }
                                            })
                                            .catch((err) => {
                                                this.logger.severe('could not remove proxy certificate from trusted device.');
                                                reject(err);
                                            });
                                    }
                                    // Remove the trusted device from the device group.
                                    deletePromises.push(this.removeDevice(device));
                                });
                                Promise.all(deletePromises)
                                    .then(() => {
                                        resolve();
                                    })
                                    .catch((err) => {
                                        reject(err);
                                    });
                            });
                    } else {
                        resolve();
                    }
                });
        });
    }

    /**
     * Get all devices in device groups defined on the proxy device
     * @param boolean to return TMOS concerns in the devices attributes
     * @returns Promise when request completes
     */
    getDevices(inlcudeHidden) {
        return new Promise((resolve, reject) => {
            const devices = [];
            this.getProxyMachineId()
                .then((machineId) => {
                    this.getDeviceGroups()
                        .then((deviceGroups) => {
                            // For each device group, query for devices.
                            const devicesPromises = [];
                            deviceGroups.map((deviceGroup) => {
                                if (deviceGroup.groupName.startsWith(DEVICEGROUP_PREFIX)) {
                                    const devicesGroupUrl = deviceGroupsUrl + '/' + deviceGroup.groupName + '/devices';
                                    const devicesGetRequest = this.restOperationFactory.createRestOperationInstance()
                                        .setUri(this.url.parse(devicesGroupUrl))
                                        .setBasicAuthorization(localauth)
                                        .setIsSetBasicAuthHeader(true);
                                    const devicesGetPromise = this.restRequestSender.sendGet(devicesGetRequest)
                                        .then((response) => {
                                            const devicesBody = response.getBody();
                                            // Return all devices in groups which are not containers.
                                            devicesBody.items.map((device, inc) => {
                                                if ((device.hasOwnProperty('mcpDeviceName') ||
                                                        device.state == UNDISCOVERED ||
                                                        inlcudeHidden
                                                    ) && (
                                                        machineId !== device.machineId)) {
                                                    const returnDevice = {
                                                        targetHost: device.address,
                                                        targetPort: device.httpsPort,
                                                        targetUUID: device.machineId,
                                                        state: device.state
                                                    };
                                                    // Add TMOS specific concerns for used for processing.
                                                    // These concerns should not be returned to clients.
                                                    if (inlcudeHidden) {
                                                        returnDevice.machineId = device.machineId;
                                                        returnDevice.url = devicesGroupUrl + '/' + device.uuid;
                                                        if (device.hasOwnProperty('mcpDeviceName') ||
                                                            device.state == UNDISCOVERED) {
                                                            returnDevice.isBigIP = true;
                                                        } else {
                                                            returnDevice.isBigIP = false;
                                                        }
                                                    }
                                                    devices.push(returnDevice);
                                                }
                                            });
                                        })
                                        .catch((err) => {
                                            this.logger.severe('Error getting devices from device group:' + err.message);
                                            reject(err);
                                        });
                                    devicesPromises.push(devicesGetPromise);
                                }
                            });
                            Promise.all(devicesPromises)
                                .then(() => {
                                    resolve(devices);
                                })
                                .catch((err) => {
                                    reject(err);
                                });
                        })
                        .catch((err) => {
                            this.logger.severe('Error getting device groups:' + err.message);
                            reject(err);
                        });
                });
        });
    }

    /**
     * Request to remove a device from the well known device group on the proxy device
     * @param the device to remove
     * @returns Promise when request completes
     */
    removeDevice(device) {
        return new Promise((resolve, reject) => {
            this.logger.info('removing ' + device.targetHost + ':' + device.targetPort + ' from device group on proxy');
            const deviceDeleteRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(device.url))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true)
                .setReferer(this.getUri().href);
            this.restRequestSender.sendDelete(deviceDeleteRequest)
                .then(() => {
                    resolve();
                })
                .catch((err) => {
                    this.logger.severe('Error removing device from device group:' + err.message);
                    reject(err);
                });
        });
    }

    /**
     * Request to remove a device certificate by its machineId from a trusted device
     * @param the trusted device to remove certificate
     * @param the machineId used to identifiy the certificate to remove
     * @returns Promise when request completes
     */
    removeCertificateFromTrustedDevice(device, machineId) {
        return new Promise((resolve, reject) => {
            this.logger.info('removing certificate for machineId: ' + machineId + ' from device ' + device.targetHost + ':' + device.targetPort);
            const certificatePromises = [];
            const certPath = '/mgmt/shared/device-certificates';
            const certUrl = 'https://' + device.targetHost + ":" + device.targetPort + certPath;
            certificatePromises.push(new Promise((resolve) => {
                const certGetRequest = this.restOperationFactory.createRestOperationInstance()
                    .setIdentifiedDeviceRequest(true)
                    .setUri(this.url.parse(certUrl))
                    .setReferer(this.getUri().href)
                    .setMethod('Get');
                this.eventChannel.emit(this.eventChannel.e.sendRestOperation, certGetRequest,
                    (response) => {
                        const certsBody = response.getBody();
                        if (certsBody.hasOwnProperty('items')) {
                            const certs = certsBody.items;
                            certs.map((cert) => {
                                certificatePromises.push(new Promise((resolve) => {
                                    if (cert.machineId == machineId) {
                                        const certDelUrl = certUrl + '/' + cert.certificateId;
                                        const certDelRequest = this.restOperationFactory.createRestOperationInstance()
                                            .setIdentifiedDeviceRequest(true)
                                            .setUri(this.url.parse(certDelUrl))
                                            .setReferer(this.getUri().href)
                                            .setMethod('Delete');
                                        this.eventChannel.emit(this.eventChannel.e.sendRestOperation, certDelRequest,
                                            (response) => {
                                                resolve();
                                            },
                                            (err) => {
                                                this.logger.severe('Error deleting certificate from remote device:' + err.message);
                                                reject(err);
                                            });
                                    }
                                }));
                            });
                            resolve();
                        }
                    },
                    (err) => {
                        reject(err);
                    }
                );
            }));
            Promise.all([certificatePromises])
                .then(() => {
                    resolve();
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    /**
     * Request to remove a device certificate by its machineId from the proxy device
     * @param the machineId used to identifiy the certificate to remove
     * @returns Promise when request completes
     */
    removeCertificateFromProxy(machineId) {
        return new Promise((resolve, reject) => {
            this.logger.info('removing certificate for machineId: ' + machineId + ' from proxy');
            const certGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(certUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true)
                .setReferer(this.getUri().href);
            const certificateGetPromise = this.restRequestSender.sendGet(certGetRequest)
                .then((response) => {
                    const certsBody = response.getBody();
                    if (certsBody.hasOwnProperty('items')) {
                        const certs = certsBody.items;
                        certs.map((cert) => {
                            if (cert.machineId == machineId) {
                                const certDelUrl = certUrl + '/' + cert.certificateId;
                                const certDelRequest = this.restOperationFactory.createRestOperationInstance()
                                    .setUri(this.url.parse(certDelUrl))
                                    .setBasicAuthorization(localauth)
                                    .setIsSetBasicAuthHeader(true)
                                    .setReferer(this.getUri().href);
                                const certDeletePromise = this.restRequestSender.sendDelete(certDelRequest);
                                certDeletePromise
                                    .then(() => {
                                        resolve();
                                    })
                                    .catch((err) => {
                                        this.logger.severe('Error deleting certificate from proxy:' + err.message);
                                        reject(err);
                                    });
                                Promise.all([certDeletePromise])
                                    .then(() => {
                                        resolve();
                                    })
                                    .catch((err) => {
                                        reject(err);
                                    });
                            }
                        });
                    }
                    resolve();
                })
                .catch((err) => {
                    this.logger.severe('Error getting certificates from proxy:' + err.message);
                    reject(err);
                });
            Promise.all([certificateGetPromise])
                .then(() => {
                    resolve();
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    /**
     * return back the proxy machine ID
     * @returns string machine UUID
     */
    getProxyMachineId() {
        return new Promise((resolve, reject) => {
            const certGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(deviceInfoUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true)
                .setReferer(this.getUri().href);
            this.restRequestSender.sendGet(certGetRequest)
                .then((response) => {
                    const deivceInfoBody = response.getBody();
                    if (deivceInfoBody.hasOwnProperty('machineId')) {
                        resolve(deivceInfoBody.machineId);
                    } else {
                        if (fs.existsSync('/machineId')) {
                            resolve(String(fs.readFileSync('/machineId', 'utf8')).replace(/[^ -~]+/g, ""));
                        } else {
                            const err = new Error('can not resolve proxy machineId');
                            reject(err);
                        }
                    }
                });
        });
    }
}

/**
 * delay timer
 * @returns Promise which resolves after timer expires
 */
const wait = (ms) => new Promise((resolve) => {
    setTimeout(resolve, ms);
});

module.exports = TrustedDevicesWorker;