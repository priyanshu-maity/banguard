
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BanGuardRegistry {
    struct ReportRecord {
        bytes32 contentHash;
        uint256 registeredAt;
        address submitter;
    }

    mapping(string => mapping(uint256 => ReportRecord)) private reports;
    mapping(string => uint256) public latestVersion;

    event ReportRegistered(string reportId, uint256 version, bytes32 contentHash, address submitter, uint256 timestamp);

    function registerReport(string calldata reportId, uint256 version, bytes32 contentHash) external {
        require(bytes(reportId).length > 0, "Empty report ID");
        require(contentHash != bytes32(0), "Empty content hash");
        require(version == latestVersion[reportId] + 1, "Invalid version");

        reports[reportId][version] = ReportRecord(contentHash, block.timestamp, msg.sender);
        latestVersion[reportId] = version;

        emit ReportRegistered(reportId, version, contentHash, msg.sender, block.timestamp);
    }

    function getReport(string calldata reportId, uint256 version) external view returns (bytes32, uint256, address) {
        ReportRecord memory report = reports[reportId][version];
        require(report.registeredAt != 0, "Report not found");

        return (report.contentHash, report.registeredAt, report.submitter);
    }
}
