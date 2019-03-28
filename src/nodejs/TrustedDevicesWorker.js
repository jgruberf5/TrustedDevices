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
const MAX_DEVICES_PER_GROUP = 10;
const DEVICE_QUERY_INTERVAL = 30000;

/**
 * delay timer
 * @returns Promise which resolves after timer expires
 */
const wait = (ms) => new Promise((resolve) => {
    setTimeout(resolve, ms);
});

/**
 * Trusted Device Controller
 * @constructor
 */
class TrustedDevicesWorker {

    constructor() {
        this.WORKER_URI_PATH = "shared/TrustedDevices";
        this.isPassThrough = true;
        this.isPublic = true;
        this.failedDevices = {};
        this.failedReasons = {};
        this.reachableDevices = {};
        if(process.env.FAILED_DEVICE_REMOVAL_MILLISECONDS) {
            this.FAILED_DEVICE_REMOVAL_MILLISECONDS = process.env.FAILED_DEVICE_REMOVAL_MILLISECONDS;
        } else {
            this.FAILED_DEVICE_REMOVAL_MILLISECONDS = 0;
        }
    }

    onStart(success) {
        setImmediate(this.validateDevices.bind(this));
        setInterval(this.validateDevices.bind(this), DEVICE_QUERY_INTERVAL);
        success();
    }

    /**
     * handle onGet HTTP request to get trusted devices
     * @param {Object} restOperation
     */
    onGet(restOperation) {
        const paths = restOperation.uri.pathname.split('/');
        const query = restOperation.uri.query;

        let targetDevice = null;

        if (query.targetHost) {
            targetDevice = query.targetHost;
        } else if (query.targetUUID) {
            targetDevice = query.targetUUID;
        } else if (paths.length > 3) {
            targetDevice = paths[3];
        }

        try {
            this.getDevices(false, targetDevice)
                .then((devices) => {
                    if (targetDevice) {
                        restOperation.statusCode = 404;
                        devices.forEach((device) => {
                            if (device.targetHost == targetDevice || device.targetUUID == targetDevice) {
                                restOperation.body = {
                                    devices: [device]
                                };
                                restOperation.statusCode = 200;
                            }
                        });
                        if (restOperation.statusCode == 200) {
                            this.completeRestOperation(restOperation);
                        } else {
                            const err = new Error('device ' + targetDevice + ' not found');
                            err.httpStatusCode = 404;
                            restOperation.fail(err);
                        }
                    } else {
                        restOperation.body = {
                            devices: devices
                        };
                        restOperation.statusCode = 200;
                        this.completeRestOperation(restOperation);
                    }
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
            this.declareDevices(declaration.devices)
                .then((declaredDevices) => {
                    restOperation.statusCode = 200;
                    restOperation.body = {
                        devices: declaredDevices
                    };
                    this.completeRestOperation(restOperation);
                })
                .catch((err) => {
                    this.logger.severe("POST request to trusted devices failed:" + err.message);
                    restOperation.fail(err);
                });
        } catch (err) {
            this.logger.severe("POST request to update trusted devices failed: \n%s", err);
            err.httpStatusCode = 400;
            restOperation.fail(err);
        }
    }

    declareDevices(desiredDevices) {
        // Create comparison collections.
        const desiredDeviceDict = {};
        const existingDeviceDict = {};
        // Populate desired comparison collection with targetHost:targetPort as the key.
        desiredDevices.forEach((device) => {
            if (!device.hasOwnProperty('targetPort')) {
                device.targetPort = 443;
            }
            desiredDeviceDict[device.targetHost + ":" + device.targetPort] = device;
        });
        let existingDevices = [];
        return this.getDevices(true)
            .then((discoveredDevices) => {
                existingDevices = discoveredDevices;
                // Populate existing comparison collection with targetHost:targetPort as the key.
                existingDevices.forEach((device) => {
                    existingDeviceDict[device.targetHost + ":" + device.targetPort] = device;
                });
                for (let device in desiredDeviceDict) {
                    if (device in existingDeviceDict) {
                        if (existingDeviceDict[device].state === ACTIVE || this.inProgress(existingDeviceDict[device].state)) {
                            if (existingDeviceDict[device].state === ACTIVE && desiredDeviceDict[device].hasOwnProperty('targetUsername') && desiredDeviceDict[device].hasOwnProperty('targetPassphrase')) {
                                // credential provided.. refresh the trust
                                this.logger.info('resetting active device ' + existingDeviceDict[device].targetHost + ':' + existingDeviceDict[device].targetPort + ' because credentials were supplied');
                            } else {
                                // Device is desired, exists already, and is active or in progress. Don't remove it.
                                existingDevices = existingDevices.filter(t => t.targetHost + ':' + t.targetPort !== device); // jshint ignore:line
                                // Device is desired, exists already, and is active or in progress. Don't add it.
                                desiredDevices = desiredDevices.filter(t => t.targetHost + ':' + t.targetPort !== device); // jshint ignore:line
                            }
                        } else {
                            this.logger.info('resetting ' + existingDeviceDict[device].targetHost + ':' + existingDeviceDict[device].targetPort + ' because its state is:' + existingDeviceDict[device].state);
                            if (!desiredDeviceDict[device].hasOwnProperty('targetUsername') ||
                                !desiredDeviceDict[device].hasOwnProperty('targetPassphrase')) {
                                const err = new Error();
                                err.message = 'declared device missing targetUsername or targetPassphrase';
                                err.httpStatusCode = 400;
                                throw err;
                            }
                        }
                    } else {
                        // Assure that the device declaration has the needed attributed to add.
                        if (!desiredDeviceDict[device].hasOwnProperty('targetUsername') ||
                            !desiredDeviceDict[device].hasOwnProperty('targetPassphrase')) {
                            const err = new Error();
                            err.message = 'declared device missing targetUsername or targetPassphrase';
                            err.httpStatusCode = 400;
                            throw err;
                        }
                    }
                }
            })
            .then(() => {
                return this.removeDevices(existingDevices);
            })
            .then(() => {
                return this.addDevices(desiredDevices);
            })
            .then(() => {
                return this.getDevices(false);
            });
    }

    /**
     * Request to get all device groups defined on the proxy device
     * @returns Promise when request completes
     */
    getDeviceGroups() {
        return this.queryDeviceGroups()
            .then((deviceGroups) => {
                if (!deviceGroups) {
                    return Promise.all([this.createDeviceGroup(`${DEVICEGROUP_PREFIX}0`)]);
                } else {
                    return Promise.resolve(deviceGroups);
                }
            });
    }

    /**
     * Request to resolve device group to add new devices
     * @returns Promise when request completes
     */

    resolveDeviceGroup() {
        // context objects
        const candidateGroups = {};
        let lastGroupIndx = 0;
        let numberOfAvailableGroups = 0;
        // flow control
        return this.queryDeviceGroups()
            .then((deviceGroups) => {
                const queryDevicesPromises = [];
                deviceGroups.forEach((deviceGroup) => {
                    candidateGroups[deviceGroup] = 0;
                    const devicesQueryPromise = this.queryDevices(deviceGroup)
                        .then((devices) => {
                            candidateGroups[deviceGroup] = devices.length;
                        });
                    queryDevicesPromises.push(devicesQueryPromise);
                });
                return Promise.all(queryDevicesPromises)
                    .then(() => {
                        // determine the highest existing index and if any device groups have capacity
                        Object.keys(candidateGroups).forEach((groupName) => {
                            const indx = parseInt(groupName.slice(DEVICEGROUP_PREFIX.length));
                            if (indx > lastGroupIndx) lastGroupIndx = indx;
                            if (candidateGroups[groupName] < MAX_DEVICES_PER_GROUP) ++numberOfAvailableGroups;
                        });
                        if (numberOfAvailableGroups === 0) {
                            // no capacity left, create a group.
                            ++lastGroupIndx;
                            return this.createDeviceGroup(DEVICEGROUP_PREFIX + lastGroupIndx);
                        } else {
                            return Promise.resolve(DEVICEGROUP_PREFIX + lastGroupIndx);
                        }
                    });
            });
    }

    /**
     * Get all devices in device groups defined on the proxy device
     * @param boolean to return TMOS concerns in the devices attributes
     * @returns Promise when request completes
     */
    getDevices(inlcudeHidden, targetDevice) {
        let proxyMachineId = null;
        return this.getProxyMachineId()
            .then((machineId) => {
                proxyMachineId = machineId;
                return this.getDeviceGroups();
            })
            .then((deviceGroups) => {
                // For each device group, query for devices.
                const devicesPromises = [];
                deviceGroups.forEach((deviceGroup) => {
                    devicesPromises.push(this.queryDevices(deviceGroup));
                });
                return Promise.all(devicesPromises);
            })
            .then((deviceResponses) => {
                const returnDevices = [];
                const devicesToRemove = [];
                deviceResponses.forEach((devices) => {
                    // Return all devices in groups which are not containers.
                    devices.forEach((device) => {
                        if (
                            (device.hasOwnProperty('mcpDeviceName') ||
                                this.inProgress(device.state) ||
                                inlcudeHidden) &&
                            (proxyMachineId !== device.machineId)
                        ) {
                            // Add devices .. ASG and BIG-IP have machineIds
                            const returnDevice = {
                                targetUUID: device.machineId,
                                targetHost: device.address,
                                targetPort: device.httpsPort,
                                state: device.state
                            };
                            // TMOS device specific attributes
                            if (device.hasOwnProperty('mcpDeviceName')) {
                                returnDevice.targetHostname = device.hostname;
                                returnDevice.targetVersion = device.version;
                                returnDevice.targetRESTVersion = device.restFrameworkVersion;
                                returnDevice.available = false;
                            }
                            if (this.reachableDevices[device.address + ':' + device.httpsPort]) {
                                returnDevice.lastValidated = this.reachableDevices[device.address + ':' + device.httpsPort];
                                returnDevice.available = true;
                            }
                            if (this.failedDevices[device.address + ':' + device.httpsPort]) {
                                returnDevice.failedSince = this.failedDevices[device.address + ':' + device.httpsPort];
                                returnDevice.failedReason = this.failedReasons[device.address + ':' + device.httpsPort];
                                returnDevice.available = false;
                            }
                            if ((device.state.indexOf('FAIL') > -1) || (device.state.indexOf('ERROR') > -1)) {
                                this.logger.severe('removing device ' + device.machineId + ' in state: ' + device.state);
                                returnDevice.machineId = device.machineId;
                                returnDevice.url = deviceGroupsUrl + '/' + device.groupName + '/devices/' + device.uuid;
                                if (device.hasOwnProperty('mcpDeviceName')) {
                                    returnDevice.isBigIP = true;
                                } else {
                                    returnDevice.isBigIP = false;
                                }
                                devicesToRemove.push(returnDevice);
                            } else {
                                // Add TMOS specific concerns for used for processing.
                                // These concerns should not be returned to clients.
                                if (inlcudeHidden) {
                                    returnDevice.machineId = device.machineId;
                                    returnDevice.url = deviceGroupsUrl + '/' + device.groupName + '/devices/' + device.uuid;
                                    if (device.hasOwnProperty('mcpDeviceName') ||
                                        this.inProgress(device.state)) {
                                        returnDevice.isBigIP = true;
                                    } else {
                                        returnDevice.isBigIP = false;
                                    }
                                }
                                // filter if needed
                                if (!targetDevice || (returnDevice.targetHost == targetDevice || returnDevice.targetUUID == targetDevice)) {
                                    returnDevices.push(returnDevice);
                                }
                            }
                        }
                    });
                });
                if (devicesToRemove.length > 0) {
                    this.removeDevices(devicesToRemove);
                }
                return Promise.resolve(returnDevices);
            });
    }

    inProgress(state) {
        let inProgress = false;
        if ((state === "PENDING") ||
            (state === "FRAMEWORK_DEPLOYMENT_PENDING") ||
            (state === "CERTIFICATE_INSTALL") ||
            (state === "PENDING_DELETE") ||
            (state === "UNDISCOVERED")) {
            inProgress = true;
        }
        return inProgress;
    }

    /**
     * Assures devices are in the well know device group on the proxy device
     * @param List of device objects to add to the device group
     * @returns Promise when assurance completes
     */
    addDevices(devicesToAdd) {
        if (devicesToAdd.length === 0) {
            return Promise.resolve();
        } else {
            const resolvePromises = [];
            let targetDeviceQueries = [];
            devicesToAdd.forEach((device) => {
                const resolvePromise = this.resolveDeviceGroup()
                    .then((deviceGroup) => {
                        return this.addDevice(deviceGroup, device)
                            .then((deviceResponse) => {
                                this.logger.info('added device id is: ' + deviceResponse.uuid);
                                targetDeviceQueries.push({
                                    deviceGroup: deviceGroup,
                                    deviceId: deviceResponse.uuid
                                });
                                resolvePromises.push(wait(1000));
                            });
                    })
                    .catch((err) => {
                        this.logger.severe(err.message);
                        throw err;
                    });
                resolvePromises.push(resolvePromise);
            });
            return Promise.all(resolvePromises)
                .then(() => {
                    const newDeviceQueries = [];
                    targetDeviceQueries.forEach((queryItems) => {
                        const deviceQuery = this.queryDevices(queryItems.deviceGroup)
                            .then((devices) => {
                                let deviceFound = false;
                                devices.forEach((device) => {
                                    if (device.uuid == queryItems.deviceId) {
                                        deviceFound = true;
                                    }
                                });
                                if (!deviceFound) {
                                    this.logger.severe('could not find added device ' + queryItems.deviceId + ' in group ' + queryItems.deviceGroup);
                                }
                                return Promise.resolve();
                            });
                        newDeviceQueries.push(deviceQuery);
                    });
                    return Promise.all(newDeviceQueries);
                })
                .catch(err => {
                    const throwErr = new Error('could not add trusted device to proxy - ' + err.message);
                    this.logger.severe(throwErr.message);
                    throw throwErr;
                });
        }
    }

    /**
     * Assures devices are no longer trusted or trust the proxy device
     * @param List of device objects to remove trust
     * @returns Promise when assurance completes
     */
    removeDevices(devicesToRemove) {
        if (devicesToRemove.length === 0) {
            return Promise.resolve();
        } else {
            const deletePromises = [];
            devicesToRemove.forEach((device) => {
                if (device.isBigIP) {
                    deletePromises.push(this.removeCertificate(device));
                }
                deletePromises.push(this.removeDevice(device));
            });
            return Promise.all(deletePromises)
                .catch((err) => {
                    const throwErr = new Error('could not remove trusted device from the proxy - ' + err.message);
                    this.logger.severe(throwErr.message);
                    throw throwErr;
                });
        }
    }

    removeCertificate(device) {
        return this.getProxyMachineId()
            .then((machineId) => {
                return this.removeCertificateFromTrustedDevice(device, machineId);
            })
            .then(() => {
                if (device.hasOwnProperty('machineId')) {
                    return this.removeCertificateFromProxy(device.machineId);
                }
            });
    }

    /**
     * Request to remove a device certificate by its machineId from a trusted device
     * @param the trusted device to remove certificate
     * @param the machineId used to identifiy the certificate to remove
     * @returns Promise when request completes
     */
    removeCertificateFromTrustedDevice(device, machineId) {
        let majorVersion = parseInt(device.targetRESTVersion.split('.')[0]);
        if (majorVersion > 12) {
            this.logger.info('removing certificate for machineId: ' + machineId + ' from device ' + device.targetHost + ':' + device.targetPort);
            const certificatePromises = [];
            return this.queryCertificatesOnRemoteDevice(device)
                .then((certificates) => {
                    certificates.forEach((cert) => {
                        if (cert.machineId == machineId) {
                            certificatePromises.push(this.deleteCertificateOnRemoveDevice(device, cert.certificateId));
                        }
                    });
                    return Promise.all([certificatePromises]);
                });
        } else {
            return Promise.resolve();
        }
    }

    /**
     * Request to remove a device certificate by its machineId from the proxy device
     * @param the machineId used to identifiy the certificate to remove
     * @returns Promise when request completes
     */

    removeCertificateFromProxy(machineId) {
        this.logger.info('removing certificate for machineId: ' + machineId + ' from proxy');
        const certificatePromises = [];
        return this.queryCertificatesOnProxy()
            .then((certificates) => {
                certificates.forEach((cert) => {
                    if (cert.machineId == machineId) {
                        certificatePromises.push(this.deleteCertificateOnProxy(cert.certificateId));
                    }
                });
                return Promise.all([certificatePromises]);
            });
    }

    /** Framework REST Requests */

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
                            return String(fs.readFileSync('/machineId', 'utf8')).replace(/[^ -~]+/g, "");
                        } else {
                            const err = new Error('can not resolve proxy machineId');
                            reject(err);
                        }
                    }
                })
                .catch((err) => {
                    const throwErr = new Error('Error get machineId on the proxy :' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    queryDeviceGroups() {
        return new Promise((resolve, reject) => {
            const deviceGroupsGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(deviceGroupsUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true);
            this.restRequestSender.sendGet(deviceGroupsGetRequest)
                .then((response) => {
                    let returnDeviceGroups = [];
                    let respBody = response.getBody();
                    if (respBody.hasOwnProperty('items')) {
                        respBody.items.forEach((deviceGroup) => {
                            if (deviceGroup.groupName.startsWith(DEVICEGROUP_PREFIX)) {
                                returnDeviceGroups.push(deviceGroup.groupName);
                            }
                        });
                    }
                    resolve(returnDeviceGroups);
                })
                .catch((err) => {
                    const throwErr = new Error('Error querying device groups:' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    queryDevices(deviceGroup) {
        return new Promise((resolve, reject) => {
            const devicesGroupUrl = deviceGroupsUrl + '/' + deviceGroup + '/devices';
            const devicesGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(devicesGroupUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true);
            this.restRequestSender.sendGet(devicesGetRequest)
                .then((response) => {
                    let returnDevices = [];
                    const devicesBody = response.getBody();
                    if (devicesBody.hasOwnProperty('items')) {
                        returnDevices = devicesBody.items;
                    }
                    resolve(returnDevices);
                })
                .catch((err) => {
                    const throwErr = new Error('Error querying devices :' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    validateDevices() {
        this.getDevices(true)
            .then((devices) => {
                devices.forEach((device) => {
                    if (device.state == ACTIVE && device.isBigIP) {
                        this.pingRemoteDevice(device)
                            .then((reachable) => {
                                if (reachable) {
                                    delete this.failedDevices[device.targetHost + ':' + device.targetPort];
                                    delete this.failedReasons[device.targetHost + ':' + device.targetPort];
                                    this.reachableDevices[device.targetHost + ':' + device.targetPort] = new Date();
                                } else {
                                    delete this.reachableDevices[device.targetHost + ':' + device.targetPort];
                                    if (this.failedDevices[device.targetHost + ':' + device.targetPort] && (this.FAILED_DEVICE_REMOVAL_MILLISECONDS > 0)) {
                                        const secLeft = new Date().getTime() - this.failedDevices[device.targetHost + ':' + device.targetPort];
                                        if (secLeft > this.FAILED_DEVICE_REMOVAL_MILLISECONDS) {
                                            this.logger.severe('could not reach active device ' + device.targetHost + ':' + device.targetPort + ' for ' + ((this.FAILED_DEVICE_REMOVAL_MILLISECONDS + secLeft) / 1000) + ' seconds.. removing trust.');
                                            this.removeDevices([device]);
                                        } else {
                                            this.logger.severe('could not reach active device ' + device.targetHost + ':' + device.targetPort + ' ' + ((this.FAILED_DEVICE_REMOVAL_MILLISECONDS - secLeft) / 1000) + ' seconds left until it will be removed from the trust.');
                                        }
                                    } else {
                                        this.failedDevices[device.targetHost + ':' + device.targetPort] = new Date();
                                    }
                                }
                            });
                    }
                });
            })
            .catch((err) => {
                this.logger.severe('could not validate devices - ' + err.message);
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
                    resolve(response.getBody().groupName);
                })
                .catch((err) => {
                    const throwErr = new Error('Error creating device group :' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    addDevice(deviceGroup, device) {
        return new Promise((resolve, reject) => {
            const devicesUrl = deviceGroupsUrl + '/' + deviceGroup + '/devices';
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
            this.restRequestSender.sendPost(devicePostRequest)
                .then((response) => {
                    this.logger.info('added ' + device.targetHost + ':' + device.targetPort + ' to proxy device group ' + deviceGroup);
                    resolve(response.getBody());
                })
                .catch((err) => {
                    const throwErr = new Error('Error adding device :' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
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
                .then((response) => {
                    resolve(response.getBody());
                })
                .catch((err) => {
                    const throwErr = new Error('Error removing device from device group:' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    queryCertificatesOnProxy() {
        return new Promise((resolve, reject) => {
            const certGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(certUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true)
                .setReferer(this.getUri().href);
            this.restRequestSender.sendGet(certGetRequest)
                .then((response) => {
                    let returnCertificates = [];
                    const certsBody = response.getBody();
                    if (certsBody.hasOwnProperty('items')) {
                        returnCertificates = certsBody.items;
                    }
                    resolve(returnCertificates);
                })
                .catch((err) => {
                    const throwErr = new Error('Error querying certificates from proxy :' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    deleteCertificateOnProxy(certificateId) {
        return new Promise((resolve, reject) => {
            const certDelUrl = certUrl + '/' + certificateId;
            const certDelRequest = this.restOperationFactory.createRestOperationInstance()
                .setUri(this.url.parse(certDelUrl))
                .setBasicAuthorization(localauth)
                .setIsSetBasicAuthHeader(true)
                .setReferer(this.getUri().href);
            this.restRequestSender.sendDelete(certDelRequest)
                .then((response) => {
                    resolve(response.getBody());
                })
                .catch((err) => {
                    const throwErr = new Error('Error deleting certificate on proxy :' + err.message);
                    this.logger.severe(throwErr.message);
                    reject(throwErr);
                });
        });
    }

    queryCertificatesOnRemoteDevice(device) {
        return new Promise((resolve, reject) => {
            const certPath = '/mgmt/shared/device-certificates';
            const certUrl = 'https://' + device.targetHost + ":" + device.targetPort + certPath;
            const certGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setIdentifiedDeviceRequest(true)
                .setUri(this.url.parse(certUrl))
                .setReferer(this.getUri().href)
                .setMethod('Get');
            this.restRequestSender.sendGet(certGetRequest)
                .then((response) => {
                    let returnCertificates = [];
                    const certsBody = response.getBody();
                    if (certsBody.hasOwnProperty('items')) {
                        returnCertificates = certsBody.items;
                    }
                    resolve(returnCertificates);
                })
                .catch((err) => {
                    const throwErr = new Error('Error querying certificate on the device :' + err.message + ' assuming offline or untrusted.');
                    this.logger.severe(throwErr.message);
                    resolve([]);
                });
        });
    }

    deleteCertificateOnRemoveDevice(device, certificateId) {
        return new Promise((resolve, reject) => {
            const certPath = '/mgmt/shared/device-certificates';
            const certUrl = 'https://' + device.targetHost + ":" + device.targetPort + certPath;
            const certDelUrl = certUrl + '/' + certificateId;
            const certDelRequest = this.restOperationFactory.createRestOperationInstance()
                .setIdentifiedDeviceRequest(true)
                .setUri(this.url.parse(certDelUrl))
                .setReferer(this.getUri().href)
                .setMethod('Delete');
            this.restRequestSender.sendDelete(certDelRequest)
                .then((response) => {
                    resolve(response.getBody());
                })
                .catch((err) => {
                    const throwErr = new Error('Error deleting certificate from device :' + err.message + ' assuming offline or untrusted');
                    this.logger.severe(throwErr.message);
                    resolve();
                });
        });
    }

    pingRemoteDevice(device) {
        return new Promise((resolve, reject) => {
            const echoPath = '/mgmt/shared/echo';
            const certUrl = 'https://' + device.targetHost + ":" + device.targetPort + echoPath;
            const certGetRequest = this.restOperationFactory.createRestOperationInstance()
                .setIdentifiedDeviceRequest(true)
                .setUri(this.url.parse(certUrl))
                .setReferer(this.getUri().href)
                .setMethod('Get');
            this.restRequestSender.sendGet(certGetRequest)
                .then(() => {
                    resolve(true);
                })
                .catch((err) => {
                    const throwErr = new Error();
                    this.failedReasons[device.targetHost + ':' + device.targetPort] = err.message;
                    this.logger.severe('Error validating trust of ' + device.targetHost + ':' + device.targetPort + ' - ' + err.message);
                    resolve(false);
                });
        });
    }

}

module.exports = TrustedDevicesWorker;