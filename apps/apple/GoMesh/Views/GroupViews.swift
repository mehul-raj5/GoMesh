import SwiftUI

/// Make a group: a name, and people picked from your chats or typed in.
struct NewGroupSheet: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @Environment(\.dismiss) private var dismiss
    let created: (String) -> Void
    @State private var name = ""
    @State private var picked: Set<String> = []
    @State private var typed = ""
    @State private var busy = false
    @State private var error: String?

    private var contacts: [String] {
        app.chats.filter { !$0.isGroup && !$0.readOnly }.map(\.name).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Group name", text: $name)
                        .foregroundStyle(theme.text)
                }
                .listRowBackground(theme.surface)
                Section("Members") {
                    ForEach(contacts, id: \.self) { c in
                        Button {
                            if picked.contains(c) { picked.remove(c) } else { picked.insert(c) }
                        } label: {
                            HStack(spacing: 12) {
                                Avatar(name: c, size: 32)
                                Text(c).foregroundStyle(theme.text)
                                Spacer()
                                Image(systemName: picked.contains(c) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(picked.contains(c) ? theme.accentText : theme.textMuted)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(picked.contains(c) ? .isSelected : [])
                    }
                    TextField("Other usernames, separated by commas", text: $typed)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                        .foregroundStyle(theme.text)
                }
                .listRowBackground(theme.surface)
                if let error {
                    Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(theme.danger) }
                        .listRowBackground(theme.surface)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .background(theme.bg)
            .navigationTitle("New group")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button("Create", action: create).disabled(!canCreate)
                    }
                }
            }
        }
    }

    private var members: [String] {
        let extra = typed.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        return Array(picked) + extra
    }

    private var canCreate: Bool { !name.trimmingCharacters(in: .whitespaces).isEmpty && !members.isEmpty }

    private func create() {
        guard canCreate, !busy else { return }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                guard let engine = app.engine else { return }
                let id = try await engine.createGroup(name: name, members: members)
                app.refreshChats()
                dismiss()
                created(id)
            } catch let e as EngineError {
                error = e.message
            } catch {}
        }
    }
}

/// A group's members, and what an admin can change.
struct GroupInfoView: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @Environment(\.dismiss) private var dismiss
    let groupID: String
    let name: String
    @State private var members: [GroupMember] = []
    @State private var adding = ""
    @State private var error: String?
    @State private var confirmLeave = false
    @State private var working = false

    private var iAmAdmin: Bool { members.first(where: \.isMe)?.isAdmin ?? false }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 10) {
                        Avatar(name: name, isGroup: true, size: 76)
                        Text(name).font(.title2.weight(.bold)).foregroundStyle(theme.text)
                        Text("\(members.count) members").font(.callout).foregroundStyle(theme.textMuted)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .listRowBackground(Color.clear)

                Section("Members") {
                    ForEach(members) { m in
                        HStack(spacing: 12) {
                            Avatar(name: m.name, size: 34)
                            Text(m.isMe ? "\(m.name) (you)" : m.name).foregroundStyle(theme.text)
                            Spacer()
                            if m.isAdmin {
                                Text("Admin")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(theme.accentText)
                                    .padding(.horizontal, 8).padding(.vertical, 3)
                                    .background(theme.accent.opacity(0.14), in: Capsule())
                            }
                            if iAmAdmin && !m.isMe {
                                Menu {
                                    if m.isAdmin {
                                        Button("Remove as admin") { act(.removeAdmin, m.name) }
                                    } else {
                                        Button("Make admin") { act(.makeAdmin, m.name) }
                                    }
                                    Button("Remove from group", role: .destructive) { act(.remove, m.name) }
                                } label: {
                                    Image(systemName: "ellipsis.circle").foregroundStyle(theme.textMuted)
                                }
                                .menuStyle(.borderlessButton)
                                .fixedSize()
                                .accessibilityLabel("Actions for \(m.name)")
                            }
                        }
                    }
                    if iAmAdmin {
                        HStack {
                            TextField("Add by username", text: $adding)
                                .autocorrectionDisabled()
                                #if os(iOS)
                                .textInputAutocapitalization(.never)
                                #endif
                                .foregroundStyle(theme.text)
                                .onSubmit(add)
                            Button("Add", action: add).disabled(adding.trimmingCharacters(in: .whitespaces).isEmpty)
                        }
                    }
                }
                .listRowBackground(theme.surface)

                if let error {
                    Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(theme.danger) }
                        .listRowBackground(theme.surface)
                }

                Section {
                    Button("Leave group", role: .destructive) { confirmLeave = true }
                        .foregroundStyle(theme.danger)
                }
                .listRowBackground(theme.surface)
            }
            .scrollContentBackground(.hidden)
            .background(theme.bg)
            .navigationTitle("Group info")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    if working { ProgressView() } else { Button("Done") { dismiss() } }
                }
            }
            .confirmationDialog("Leave \(name)?", isPresented: $confirmLeave, titleVisibility: .visible) {
                Button("Leave", role: .destructive) {
                    act(.leave, "")
                    dismiss()
                }
            } message: {
                Text("You'll stop getting its messages. What's here stays readable on this device.")
            }
            .task(id: app.chats) { await load() }
        }
    }

    private func load() async {
        guard let engine = app.engine else { return }
        do { members = try await engine.groupMembers(groupID) }
        catch let e as EngineError { error = e.message }
        catch {}
    }

    private func add() {
        let name = adding.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        adding = ""
        act(.add, name)
    }

    /// Changes take a signed round trip; the members list catches up when the
    /// change lands, and a refusal comes up as a message.
    private func act(_ action: Engine.GroupAction, _ username: String) {
        error = nil
        working = true
        Task {
            defer { working = false }
            do {
                try await app.engine?.groupAction(groupID, action, username: username)
                try? await Task.sleep(for: .milliseconds(600))
                await load()
            } catch let e as EngineError {
                error = e.message
            } catch {}
        }
    }
}
