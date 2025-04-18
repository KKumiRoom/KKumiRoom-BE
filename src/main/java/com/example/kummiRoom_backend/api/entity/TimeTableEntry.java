package com.example.kummiRoom_backend.api.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "timetable_entry")
public class TimeTableEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long entryId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "course_id")
    private Course course;

    private Integer period;
    private String day;
    private Integer semester;
}
